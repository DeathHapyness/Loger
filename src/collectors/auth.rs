//! Autenticação: logins aceitos (com método e fingerprint da chave), falhas, usuários
//! inválidos, força bruta e sudo/su negados.
//!
//! Fontes, na ordem: arquivo de log do syslog (auth.log/secure); se não houver, journalctl;
//! se não houver, /var/log/btmp (registro binário de falhas, presente em todo Linux com sshd).

use super::Ctx;
use crate::event::{Ev, ALERT, INFO, NOTICE, WARN};
use serde_json::json;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

struct Brute {
    window_start: Instant,
    count: u32,
    users: Vec<String>,
}

struct Parser {
    ctx: Ctx,
    threshold: u32,
    per_ip: HashMap<String, Brute>,
}

/// Pega a palavra que vem depois de `key` (ex: after("from 1.2.3.4 port", "from") = "1.2.3.4").
fn after<'a>(s: &'a str, key: &str) -> Option<&'a str> {
    let i = s.find(key)? + key.len();
    s[i..].split_whitespace().next()
}

impl Parser {
    fn line(&mut self, line: &str) {
        // Formato syslog: "... prog[pid]: mensagem"
        let Some((head, msg)) = line.split_once("]: ").or_else(|| line.split_once(": ")) else { return };
        let prog = head.rsplit(' ').next().unwrap_or("").split('[').next().unwrap_or("");
        if prog.starts_with("sshd") {
            self.sshd(msg);
        } else if prog == "sudo" {
            self.sudo(msg);
        } else if prog == "su" {
            self.su(msg);
        }
    }

    fn sshd(&mut self, msg: &str) {
        if let Some(rest) = msg.strip_prefix("Accepted ") {
            // Accepted publickey for joao from 1.2.3.4 port 5555 ssh2: ED25519 SHA256:abc
            let method = rest.split_whitespace().next().unwrap_or("");
            let user = after(rest, " for ").unwrap_or("");
            let ip = after(rest, " from ").unwrap_or("");
            let port = after(rest, " port ").unwrap_or("");
            let key = rest.split_once("ssh2: ").map(|x| x.1.trim()).unwrap_or("");
            let mut m = format!("login SSH aceito de {}:{} via {}", ip, port, method);
            if !key.is_empty() {
                m.push_str(&format!(" (chave {})", key));
            }
            self.ctx.send(Ev::new("ssh.auth_ok", NOTICE, m).user(user).data(json!({
                "method": method, "ip": ip, "port": port, "key": key,
            })));
        } else if let Some(rest) = msg.strip_prefix("Failed ") {
            // Failed password for [invalid user] joao from 1.2.3.4 port 5555 ssh2
            let method = rest.split_whitespace().next().unwrap_or("");
            let invalid = rest.contains(" for invalid user ");
            let user = if invalid { after(rest, "invalid user ") } else { after(rest, " for ") }.unwrap_or("");
            let ip = after(rest, " from ").unwrap_or("").to_string();
            let port = after(rest, " port ").unwrap_or("");
            self.fail(&ip, user, &format!(
                "falha de login SSH ({}) de {}:{}{}", method, ip, port, if invalid { " — usuário inexistente" } else { "" }
            ), json!({ "method": method, "ip": ip, "port": port, "invalid_user": invalid }));
        } else if msg.starts_with("Invalid user ") {
            // "Invalid user x from ip port n" -> já vem um "Failed" depois; ignorado para não duplicar.
        } else if msg.contains("maximum authentication attempts exceeded") {
            let user = after(msg, " for ").unwrap_or("");
            let ip = after(msg, " from ").unwrap_or("");
            self.ctx.send(Ev::new("ssh.auth_max", WARN, format!("máximo de tentativas excedido de {}", ip))
                .user(user).data(json!({ "ip": ip })));
        }
    }

    fn fail(&mut self, ip: &str, user: &str, msg: &str, data: serde_json::Value) {
        let b = self.per_ip.entry(ip.to_string()).or_insert(Brute { window_start: Instant::now(), count: 0, users: vec![] });
        if b.window_start.elapsed() > Duration::from_secs(60) {
            *b = Brute { window_start: Instant::now(), count: 0, users: vec![] };
        }
        b.count += 1;
        if !b.users.iter().any(|u| u == user) && b.users.len() < 20 {
            b.users.push(user.to_string());
        }
        // As primeiras falhas de cada IP são registradas uma a uma; depois vira um resumo.
        if b.count <= 3 {
            self.ctx.send(Ev::new("ssh.auth_fail", WARN, msg).user(user).data(data));
        }
        if b.count == self.threshold {
            self.ctx.send(Ev::new(
                "ssh.bruteforce",
                ALERT,
                format!("possível força bruta: {} falhas de {} em menos de 60s (usuários: {})", b.count, ip, b.users.join(", ")),
            ).data(json!({ "ip": ip, "failures": b.count, "users": b.users })));
        }
    }

    fn sudo(&mut self, msg: &str) {
        // "joao : 3 incorrect password attempts ; TTY=pts/0 ; ... COMMAND=/bin/bash"
        // "joao : user NOT in sudoers ; TTY=..."
        let user = msg.split(" : ").next().unwrap_or("").trim();
        let cmd = msg.split("COMMAND=").nth(1).unwrap_or("").trim();
        if msg.contains("incorrect password attempt") || msg.contains("NOT in sudoers")
            || msg.contains("command not allowed") || msg.contains("a password is required")
        {
            let reason = msg.split(" : ").nth(1).unwrap_or("").split(" ; ").next().unwrap_or("").trim();
            self.ctx.send(Ev::new("priv.sudo_denied", ALERT, format!("sudo NEGADO ({}): {}", reason, cmd))
                .user(user).data(json!({ "reason": reason, "command": cmd })));
        } else if msg.contains("authentication failure") && msg.contains("pam_unix(sudo") {
            let u = after(msg, " ruser=").or_else(|| after(msg, " user=")).unwrap_or("");
            self.ctx.send(Ev::new("priv.sudo_auth_fail", WARN, "senha errada no sudo").user(u));
        }
    }

    fn su(&mut self, msg: &str) {
        if msg.starts_with("FAILED SU") || (msg.contains("authentication failure") && msg.contains("pam_unix(su")) {
            let u = after(msg, " ruser=").or_else(|| after(msg, "by ")).unwrap_or("");
            self.ctx.send(Ev::new("priv.su_fail", WARN, format!("su falhou: {}", msg.trim())).user(u));
        }
    }
}

/// Segue um arquivo de texto como `tail -F` (aguenta rotação e truncamento).
fn tail_file(path: &Path, p: &mut Parser) {
    let mut file: Option<(BufReader<File>, u64)> = None;
    let mut first = true;
    let mut line = String::new();
    loop {
        if file.is_none() {
            if let Ok(f) = File::open(path) {
                let ino = f.metadata().map(|m| m.ino()).unwrap_or(0);
                let mut r = BufReader::new(f);
                if first {
                    let _ = r.seek(SeekFrom::End(0));
                }
                file = Some((r, ino));
            }
            first = false;
        }
        let mut got = false;
        if let Some((r, _)) = file.as_mut() {
            loop {
                line.clear();
                match r.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) if !line.ends_with('\n') => {
                        // Linha incompleta: volta e espera o resto.
                        let _ = r.seek(SeekFrom::Current(-(line.len() as i64)));
                        break;
                    }
                    Ok(_) => {
                        got = true;
                        p.line(line.trim_end());
                    }
                    Err(_) => break,
                }
            }
        }
        if !got {
            std::thread::sleep(Duration::from_millis(500));
            // Rotação: o caminho aponta para outro inode, ou o arquivo encolheu.
            if let Some((r, ino)) = file.as_mut() {
                let pos = r.stream_position().unwrap_or(0);
                match std::fs::metadata(path) {
                    Ok(md) if md.ino() != *ino || md.len() < pos => file = None,
                    Err(_) => file = None,
                    _ => {}
                }
            }
        }
    }
}

fn run_journal(p: &mut Parser) -> bool {
    let child = Command::new("journalctl")
        .args(["-f", "-n", "0", "-o", "short", "_COMM=sshd", "_COMM=sshd-session", "_COMM=sudo", "_COMM=su"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let Ok(mut child) = child else { return false };
    let out = child.stdout.take().unwrap();
    for line in BufReader::new(out).lines().map_while(Result::ok) {
        p.line(&line);
    }
    let _ = child.wait();
    true
}

/// /var/log/btmp: registros binários de 384 bytes (struct utmp) com logins que falharam.
fn tail_btmp(path: &Path, p: &mut Parser) {
    let mut pos = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    loop {
        std::thread::sleep(Duration::from_secs(1));
        let len = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        if len < pos {
            pos = 0;
        }
        if len - pos < 384 {
            continue;
        }
        let Ok(mut f) = File::open(path) else { continue };
        let _ = f.seek(SeekFrom::Start(pos));
        let mut buf = vec![0u8; (len - pos) as usize / 384 * 384];
        if f.read_exact(&mut buf).is_err() {
            continue;
        }
        pos += buf.len() as u64;
        for rec in buf.chunks(384) {
            let s = |r: std::ops::Range<usize>| {
                String::from_utf8_lossy(&rec[r]).trim_end_matches('\0').to_string()
            };
            let line = s(8..40);
            let user = s(44..76);
            let host = s(76..332);
            p.fail(&host, &user, &format!("falha de login ({}) de {}", line, host), json!({ "ip": host, "line": line }));
        }
    }
}

pub fn run(ctx: Ctx) {
    let cfg = ctx.cfg.auth.clone();
    let mut p = Parser { ctx: ctx.clone(), threshold: cfg.bruteforce_threshold.max(2), per_ip: HashMap::new() };
    if let Some(path) = cfg.files.iter().map(Path::new).find(|p| p.exists()) {
        ctx.send(Ev::new("loger.collector", INFO, format!("autenticação: lendo {}", path.display())));
        tail_file(path, &mut p);
    }
    if Path::new("/run/systemd/journal").exists() {
        ctx.send(Ev::new("loger.collector", INFO, "autenticação: lendo o journal do systemd"));
        if run_journal(&mut p) {
            ctx.send(Ev::new("loger.collector", WARN, "autenticação: journalctl terminou inesperadamente"));
        }
    }
    let btmp = Path::new("/var/log/btmp");
    if btmp.exists() {
        ctx.send(Ev::new("loger.collector", NOTICE, "autenticação: só /var/log/btmp disponível (apenas falhas de login)"));
        tail_btmp(btmp, &mut p);
    }
    ctx.send(Ev::new("loger.collector", WARN, "autenticação: nenhuma fonte encontrada (auth.log, journal ou btmp)"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{mpsc, Arc};

    fn parse(lines: &[&str]) -> Vec<Ev> {
        let (tx, rx) = mpsc::sync_channel(100);
        let ctx = Ctx { tx, cfg: Arc::new(Default::default()) };
        let mut p = Parser { ctx, threshold: 3, per_ip: HashMap::new() };
        for l in lines {
            p.line(l);
        }
        drop(p);
        rx.try_iter().collect()
    }

    #[test]
    fn accepted_key() {
        let ev = parse(&["Oct  4 12:00:01 srv sshd-session[123]: Accepted publickey for joao from 10.0.0.9 port 51234 ssh2: ED25519 SHA256:AbCd"]);
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].kind, "ssh.auth_ok");
        assert_eq!(ev[0].user, "joao");
        assert_eq!(ev[0].data["key"], "ED25519 SHA256:AbCd");
    }

    #[test]
    fn bruteforce() {
        let l = "2026-10-04T12:00:01.000000-03:00 srv sshd[9]: Failed password for invalid user admin from 1.2.3.4 port 22 ssh2";
        let ev = parse(&[l, l, l, l, l]);
        assert_eq!(ev.iter().filter(|e| e.kind == "ssh.auth_fail").count(), 3);
        assert_eq!(ev.iter().filter(|e| e.kind == "ssh.bruteforce").count(), 1);
        assert_eq!(ev[0].user, "admin");
    }

    #[test]
    fn sudo_denied() {
        let ev = parse(&["Oct  4 12:00:01 srv sudo[5]:    maria : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/maria ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"]);
        assert_eq!(ev[0].kind, "priv.sudo_denied");
        assert_eq!(ev[0].user, "maria");
    }
}
