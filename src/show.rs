//! `loger show`: consulta e filtros sobre os logs gravados.

use crate::event::{level_rank, Record};
use crate::store::{self, BASE};
use crate::util::{fmt_local, parse_when};
use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;

#[derive(Default)]
pub struct Filter {
    pub kinds: Vec<String>,
    pub user: Option<String>,
    pub since: Option<u64>,
    pub until: Option<u64>,
    pub min_level: u8,
    pub grep: Option<String>,
    pub ses: Option<u64>,
    pub last: Option<usize>,
    pub follow: bool,
    pub json: bool,
}

impl Filter {
    pub fn parse(args: &[String]) -> Result<Filter, String> {
        let mut f = Filter::default();
        let mut it = args.iter();
        while let Some(a) = it.next() {
            let mut val = |name: &str| it.next().cloned().ok_or(format!("{} precisa de um valor", name));
            match a.as_str() {
                "-k" | "--kind" => f.kinds.extend(val(a)?.split(',').map(String::from)),
                "-u" | "--user" => f.user = Some(val(a)?),
                "-s" | "--since" => f.since = Some(parse_when(&val(a)?).ok_or("data inválida em --since")?),
                "--until" => f.until = Some(parse_when(&val(a)?).ok_or("data inválida em --until")?),
                "-l" | "--level" => f.min_level = level_rank(&val(a)?),
                "-g" | "--grep" => f.grep = Some(val(a)?.to_lowercase()),
                "--ses" => f.ses = Some(val(a)?.parse().map_err(|_| "--ses precisa de um número")?),
                "-n" => f.last = Some(val(a)?.parse().map_err(|_| "-n precisa de um número")?),
                "-f" | "--follow" => f.follow = true,
                "--json" => f.json = true,
                "-d" | "--dir" | "-c" | "--config" => {
                    it.next();
                }
                o => return Err(format!("opção desconhecida: {}", o)),
            }
        }
        Ok(f)
    }

    fn matches(&self, r: &Record) -> bool {
        if !self.kinds.is_empty() && !self.kinds.iter().any(|k| r.kind == *k || r.kind.starts_with(&format!("{}.", k))) {
            return false;
        }
        if let Some(u) = &self.user {
            if r.user != *u {
                return false;
            }
        }
        if level_rank(&r.level) < self.min_level {
            return false;
        }
        if self.since.is_some() || self.until.is_some() {
            let t = r.ts_ms();
            if self.since.map(|s| t < s).unwrap_or(false) || self.until.map(|u| t > u).unwrap_or(false) {
                return false;
            }
        }
        if let Some(s) = self.ses {
            if r.data.get("ses").and_then(|v| v.as_u64()) != Some(s) {
                return false;
            }
        }
        if let Some(g) = &self.grep {
            if !r.msg.to_lowercase().contains(g) && !r.data.to_string().to_lowercase().contains(g) {
                return false;
            }
        }
        true
    }
}

fn color() -> bool {
    (unsafe { libc::isatty(1) == 1 }) && std::env::var_os("NO_COLOR").is_none()
}

fn print(r: &Record, json: bool, color: bool, line: &str) {
    if json {
        println!("{}", line);
        return;
    }
    let (c, lvl) = match r.level.as_str() {
        "alert" => ("\x1b[1;31m", "ALERTA"),
        "warn" => ("\x1b[33m", "AVISO "),
        "notice" => ("\x1b[36m", "NOTA  "),
        _ => ("\x1b[2m", "info  "),
    };
    let (c, dim, rst) = if color { (c, "\x1b[2m", "\x1b[0m") } else { ("", "", "") };
    let ses = r.data.get("ses").and_then(|v| v.as_u64()).map(|s| format!(" {}[ses {}]{}", dim, s, rst)).unwrap_or_default();
    println!(
        "{} {}{}{} {:<22} {:<12} {}{}",
        fmt_local(r.ts_ms()), c, lvl, rst, r.kind, if r.user.is_empty() { "-" } else { &r.user }, r.msg, ses
    );
}

pub fn show(dir: &Path, f: &Filter) -> Result<(), String> {
    let color = color();
    let mut ring: VecDeque<(Record, String)> = VecDeque::new();
    store::for_each_line(dir, |_, _, line| {
        let Ok(r) = serde_json::from_str::<Record>(line) else { return };
        if !f.matches(&r) {
            return;
        }
        match f.last {
            Some(n) => {
                ring.push_back((r, line.to_string()));
                if ring.len() > n {
                    ring.pop_front();
                }
            }
            None => print(&r, f.json, color, line),
        }
    })
    .map_err(|e| format!("{} (rode como root?)", e))?;
    for (r, l) in &ring {
        print(r, f.json, color, l);
    }
    if f.follow {
        follow(dir, f, color);
    }
    Ok(())
}

fn follow(dir: &Path, f: &Filter, color: bool) {
    let path = dir.join(BASE);
    let open = || -> Option<(BufReader<File>, u64)> {
        let file = File::open(&path).ok()?;
        let ino = file.metadata().ok()?.ino();
        Some((BufReader::new(file), ino))
    };
    let Some((mut r, mut ino)) = open() else { return };
    let _ = r.seek(SeekFrom::End(0));
    let mut line = String::new();
    loop {
        line.clear();
        match r.read_line(&mut line) {
            Ok(n) if n > 0 && line.ends_with('\n') => {
                if let Ok(rec) = serde_json::from_str::<Record>(line.trim_end()) {
                    if f.matches(&rec) {
                        print(&rec, f.json, color, line.trim_end());
                    }
                }
            }
            Ok(n) => {
                if n > 0 {
                    let _ = r.seek(SeekFrom::Current(-(n as i64)));
                }
                std::thread::sleep(Duration::from_millis(300));
                // Arquivo rotacionado: passa para o novo.
                if std::fs::metadata(&path).map(|m| m.ino() != ino).unwrap_or(false) {
                    if let Some((nr, ni)) = open() {
                        r = nr;
                        ino = ni;
                    }
                }
            }
            Err(_) => return,
        }
    }
}
