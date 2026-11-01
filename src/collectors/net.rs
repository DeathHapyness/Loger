//! Rede: portas novas em escuta e conexões de saída, lendo /proc/net/{tcp,tcp6,udp,udp6}.
//! Funciona em qualquer Linux. Por ser por amostragem, conexões muito curtas podem escapar.

use super::Ctx;
use crate::event::{Ev, ALERT, NOTICE, WARN};
use crate::procfs;
use crate::users::{Users, NO_UID};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Sock {
    pub proto: &'static str,
    pub local: String,
    pub local_port: u16,
    pub remote: String,
    pub remote_port: u16,
    pub state: u8,
    pub inode: u64,
}

const ESTABLISHED: u8 = 0x01;
const LISTEN: u8 = 0x0A;
const SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "ksh", "fish", "ash", "csh", "tcsh"];

fn parse_addr(s: &str) -> Option<(String, u16)> {
    let (ip, port) = s.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let ip = match ip.len() {
        8 => Ipv4Addr::from(u32::from_str_radix(ip, 16).ok()?.to_ne_bytes()).to_string(),
        32 => {
            let mut b = [0u8; 16];
            for i in 0..4 {
                let w = u32::from_str_radix(&ip[i * 8..i * 8 + 8], 16).ok()?;
                b[i * 4..i * 4 + 4].copy_from_slice(&w.to_ne_bytes());
            }
            let v6 = Ipv6Addr::from(b);
            match v6.to_ipv4_mapped() {
                Some(v4) => v4.to_string(),
                None => v6.to_string(),
            }
        }
        _ => return None,
    };
    Some((ip, port))
}

pub fn read_sockets() -> Vec<Sock> {
    let mut out = Vec::new();
    for (file, proto) in [("tcp", "tcp"), ("tcp6", "tcp"), ("udp", "udp"), ("udp6", "udp")] {
        let Ok(text) = std::fs::read_to_string(format!("/proc/net/{}", file)) else { continue };
        for line in text.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 10 {
                continue;
            }
            let (Some((local, lp)), Some((remote, rp))) = (parse_addr(f[1]), parse_addr(f[2])) else { continue };
            out.push(Sock {
                proto,
                local,
                local_port: lp,
                remote,
                remote_port: rp,
                state: u8::from_str_radix(f[3], 16).unwrap_or(0),
                inode: f[9].parse().unwrap_or(0),
            });
        }
    }
    out
}

/// Mapa inode do socket -> pid dono (varre /proc/*/fd).
fn socket_owners() -> HashMap<u64, i32> {
    let mut m = HashMap::new();
    for pid in procfs::all_pids() {
        for ino in procfs::socket_inodes(pid) {
            m.entry(ino).or_insert(pid);
        }
    }
    m
}

/// IP:porta do outro lado de uma conexão TCP estabelecida do processo (usado para achar
/// o IP de origem de uma sessão SSH a partir do processo do sshd).
pub fn tcp_peer_of(pid: i32) -> Option<String> {
    let inodes: HashSet<u64> = procfs::socket_inodes(pid).into_iter().collect();
    if inodes.is_empty() {
        return None;
    }
    read_sockets()
        .into_iter()
        .find(|s| s.proto == "tcp" && s.state == ESTABLISHED && inodes.contains(&s.inode))
        .map(|s| format!("{}:{}", s.remote, s.remote_port))
}

/// Faixa de portas efêmeras (usadas por clientes); UDP nessa faixa não é "serviço".
fn ephemeral() -> (u16, u16) {
    crate::util::read_text("/proc/sys/net/ipv4/ip_local_port_range", 64)
        .and_then(|s| {
            let v: Vec<u16> = s.split_whitespace().filter_map(|x| x.parse().ok()).collect();
            Some((*v.first()?, *v.get(1)?))
        })
        .unwrap_or((32768, 60999))
}

fn is_listener(s: &Sock, eph: (u16, u16)) -> bool {
    match s.proto {
        "tcp" => s.state == LISTEN,
        _ => s.remote_port == 0 && s.local_port != 0 && !(eph.0..=eph.1).contains(&s.local_port),
    }
}

pub fn run(ctx: Ctx) {
    let cfg = ctx.cfg.net.clone();
    let mut users = Users::new();
    let me = std::process::id() as i32;
    let key_l = |s: &Sock| format!("{}/{}:{}", s.proto, s.local, s.local_port);
    let key_c = |s: &Sock| format!("{}:{}>{}:{}", s.local, s.local_port, s.remote, s.remote_port);

    let eph = ephemeral();
    // Estado inicial: não gera eventos, só registra o inventário de portas abertas.
    let first = read_sockets();
    let mut listeners: HashSet<String> = first.iter().filter(|s| is_listener(s, eph)).map(key_l).collect();
    let mut conns: HashSet<String> =
        first.iter().filter(|s| s.proto == "tcp" && s.state == ESTABLISHED).map(key_c).collect();
    let mut inv: Vec<&String> = listeners.iter().collect();
    inv.sort();
    ctx.send(
        Ev::new("net.inventory", NOTICE, format!("{} portas em escuta no início", inv.len()))
            .data(json!({ "listening": inv })),
    );

    loop {
        std::thread::sleep(Duration::from_millis(cfg.interval_ms.max(200)));
        let socks = read_sockets();
        let listen_ports: HashSet<u16> =
            socks.iter().filter(|s| s.proto == "tcp" && s.state == LISTEN).map(|s| s.local_port).collect();

        let now_l: HashMap<String, &Sock> = socks.iter().filter(|s| is_listener(s, eph)).map(|s| (key_l(s), s)).collect();
        let now_c: HashMap<String, &Sock> = socks
            .iter()
            .filter(|s| s.proto == "tcp" && s.state == ESTABLISHED)
            .map(|s| (key_c(s), s))
            .collect();

        let new_l: Vec<&Sock> = now_l.iter().filter(|(k, _)| !listeners.contains(*k)).map(|(_, s)| *s).collect();
        // Conexão de saída = porta local não é uma porta em que a máquina escuta.
        let new_c: Vec<&Sock> = now_c
            .iter()
            .filter(|(k, s)| !conns.contains(*k) && !listen_ports.contains(&s.local_port) && s.remote != "127.0.0.1" && s.remote != "::1")
            .map(|(_, s)| *s)
            .collect();

        if (cfg.listen && !new_l.is_empty()) || (cfg.outbound && !new_c.is_empty()) {
            let owners = socket_owners();
            if cfg.listen {
                for s in &new_l {
                    let p = owners.get(&s.inode).and_then(|&pid| procfs::read(pid, 1024));
                    if p.as_ref().map(|p| p.pid == me).unwrap_or(false) {
                        continue;
                    }
                    let (who, user, data) = describe(&p, &mut users);
                    ctx.send(
                        Ev::new("net.listen", WARN, format!("nova porta aberta {} {}:{} por {}", s.proto, s.local, s.local_port, who))
                            .user(user)
                            .data(json!({ "proto": s.proto, "addr": s.local, "port": s.local_port, "process": data })),
                    );
                }
            }
            if cfg.outbound {
                for s in &new_c {
                    let p = owners.get(&s.inode).and_then(|&pid| procfs::read(pid, 1024));
                    let Some(pi) = &p else { continue };
                    if pi.pid == me || (cfg.only_sessions && pi.auid == NO_UID) {
                        continue;
                    }
                    let shell = SHELLS.contains(&crate::util::basename(&pi.exe));
                    let (who, user, data) = describe(&p, &mut users);
                    let (kind, level, msg) = if shell {
                        ("net.shell_socket", ALERT, format!("SHELL com conexão de rede para {}:{} ({}) — possível reverse shell", s.remote, s.remote_port, who))
                    } else {
                        ("net.connect", NOTICE, format!("conexão de saída para {}:{} por {}", s.remote, s.remote_port, who))
                    };
                    ctx.send(
                        Ev::new(kind, level, msg).user(user).data(json!({
                            "local": format!("{}:{}", s.local, s.local_port),
                            "remote": s.remote, "remote_port": s.remote_port, "process": data,
                        })),
                    );
                }
            }
        }

        for k in listeners.iter().filter(|k| !now_l.contains_key(*k)) {
            ctx.send(Ev::new("net.listen_closed", NOTICE, format!("porta fechada {}", k)).data(json!({ "socket": k })));
        }
        listeners = now_l.into_keys().collect();
        conns = now_c.into_keys().collect();
    }
}

fn describe(p: &Option<procfs::ProcInfo>, users: &mut Users) -> (String, String, serde_json::Value) {
    match p {
        None => ("processo desconhecido".into(), String::new(), serde_json::Value::Null),
        Some(p) => {
            let user = users.name(p.auid);
            (
                format!("{} (pid {})", p.exe, p.pid),
                user,
                json!({ "pid": p.pid, "exe": p.exe, "argv": p.argv, "uid": p.uid, "auid": p.auid, "ses": p.ses }),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn addr() {
        assert_eq!(super::parse_addr("0100007F:0016"), Some(("127.0.0.1".into(), 22)));
        assert_eq!(
            super::parse_addr("0000000000000000FFFF00000100007F:0050"),
            Some(("127.0.0.1".into(), 80))
        );
    }
}
