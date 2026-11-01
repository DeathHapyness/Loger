//! Leitura de informações de processos em /proc/<pid>.

use crate::util::read_text;
use std::fs;

#[derive(Debug, Clone, Default)]
pub struct ProcInfo {
    pub pid: i32,
    pub ppid: i32,
    pub uid: u32,
    pub euid: u32,
    pub auid: u32,
    pub ses: u32,
    pub start: u64,
    pub comm: String,
    pub exe: String,
    pub exe_deleted: bool,
    pub cwd: String,
    pub tty: String,
    pub argv: Vec<String>,
}

/// Lê tudo de um processo. `None` se ele já terminou.
pub fn read(pid: i32, max_args: usize) -> Option<ProcInfo> {
    let mut p = ProcInfo { pid, ..Default::default() };
    let base = format!("/proc/{}", pid);

    let status = read_text(format!("{}/status", base), 8192)?;
    for line in status.lines() {
        if let Some(v) = line.strip_prefix("Name:") {
            p.comm = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("PPid:") {
            p.ppid = v.trim().parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("Uid:") {
            let ids: Vec<u32> = v.split_whitespace().filter_map(|x| x.parse().ok()).collect();
            p.uid = *ids.first().unwrap_or(&0);
            p.euid = *ids.get(1).unwrap_or(&0);
        }
    }
    let (auid, ses) = login_ids(pid);
    p.auid = auid;
    p.ses = ses;

    if let Some(stat) = read_text(format!("{}/stat", base), 4096) {
        // Os campos depois do nome do processo "(comm)" são separados por espaço.
        if let Some(rest) = stat.rsplit_once(')').map(|x| x.1) {
            let f: Vec<&str> = rest.split_whitespace().collect();
            p.tty = tty_name(f.get(4).and_then(|x| x.parse().ok()).unwrap_or(0));
            p.start = f.get(19).and_then(|x| x.parse().ok()).unwrap_or(0);
        }
    }

    if let Ok(exe) = fs::read_link(format!("{}/exe", base)) {
        let s = exe.to_string_lossy();
        if let Some(stripped) = s.strip_suffix(" (deleted)") {
            p.exe = stripped.to_string();
            p.exe_deleted = true;
        } else {
            p.exe = s.into_owned();
        }
    }
    p.cwd = fs::read_link(format!("{}/cwd", base)).map(|c| c.to_string_lossy().into_owned()).unwrap_or_default();
    p.argv = argv(pid, max_args);
    Some(p)
}

/// Instante de início do processo (em ticks desde o boot). Junto com o pid, identifica
/// o processo de forma única mesmo quando o pid é reutilizado.
pub fn read_text_start(pid: i32) -> Option<u64> {
    let stat = read_text(format!("/proc/{}/stat", pid), 4096)?;
    stat.rsplit_once(')')?.1.split_whitespace().nth(19)?.parse().ok()
}

pub fn argv(pid: i32, max: usize) -> Vec<String> {
    let Some(raw) = read_bytes(&format!("/proc/{}/cmdline", pid), max) else { return vec![] };
    let mut v: Vec<String> = raw.split(|&b| b == 0).map(|s| String::from_utf8_lossy(s).into_owned()).collect();
    while v.last().map(|s| s.is_empty()).unwrap_or(false) {
        v.pop();
    }
    if raw.len() >= max {
        v.push("…(truncado)".into());
    }
    v
}

/// loginuid e sessionid: definidos pelo PAM no login e herdados por tudo que o usuário roda,
/// inclusive depois de `sudo` ou `su`. É o que liga um comando ao login original.
pub fn login_ids(pid: i32) -> (u32, u32) {
    let rd = |f: &str| {
        read_text(format!("/proc/{}/{}", pid, f), 32)
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(u32::MAX)
    };
    (rd("loginuid"), rd("sessionid"))
}

pub fn env_var(pid: i32, name: &str) -> Option<String> {
    let raw = read_bytes(&format!("/proc/{}/environ", pid), 256 * 1024)?;
    let prefix = format!("{}=", name);
    raw.split(|&b| b == 0)
        .map(|s| String::from_utf8_lossy(s))
        .find(|s| s.starts_with(&prefix))
        .map(|s| s[prefix.len()..].to_string())
}

fn read_bytes(path: &str, max: usize) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut buf = Vec::new();
    fs::File::open(path).ok()?.take(max as u64).read_to_end(&mut buf).ok()?;
    Some(buf)
}

fn tty_name(nr: u64) -> String {
    let major = (nr >> 8) & 0xfff;
    let minor = (nr & 0xff) | ((nr >> 12) & 0xfff00);
    match major {
        0 => String::new(),
        136..=143 => format!("pts/{}", (major - 136) * 256 + minor),
        4 if minor < 64 => format!("tty{}", minor),
        4 => format!("ttyS{}", minor - 64),
        _ => format!("tty({}:{})", major, minor),
    }
}

/// Todos os PIDs (processos, não threads) existentes agora.
pub fn all_pids() -> Vec<i32> {
    fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse().ok())
        .collect()
}

/// Inodes de sockets abertos por um processo.
pub fn socket_inodes(pid: i32) -> Vec<u64> {
    fs::read_dir(format!("/proc/{}/fd", pid))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let l = fs::read_link(e.path()).ok()?;
            let s = l.to_str()?;
            s.strip_prefix("socket:[")?.strip_suffix(']')?.parse().ok()
        })
        .collect()
}
