//! Processos e sessões.
//!
//! Fonte principal: o "proc connector" do kernel (netlink), que avisa a cada fork/exec/exit
//! e mudança de uid. Existe em praticamente todo kernel Linux desde 2.6.15 e não precisa de
//! nada instalado. Se não estiver disponível (sem root, container restrito), cai para
//! varredura periódica de /proc.
//!
//! Sessões: o PAM grava um loginuid/sessionid em cada login, e eles são herdados por todos
//! os processos do usuário, mesmo depois de `sudo`/`su`. Assim cada comando fica ligado ao
//! login que o originou.

use super::{net, Ctx};
use crate::event::{Ev, ALERT, INFO, NOTICE, WARN};
use crate::procfs::{self, ProcInfo};
use crate::users::{Users, NO_UID};
use crate::util::{basename, join_argv, now_ms};
use serde_json::json;
use std::collections::HashMap;
use std::io;
use std::time::{Duration, Instant};

#[derive(Clone)]
struct Proc {
    ppid: i32,
    uid: u32,
    euid: u32,
    auid: u32,
    ses: u32,
    start: u64,
    exe: String,
    argv: Vec<String>,
}

struct Session {
    auid: u32,
    user: String,
    start_ms: u64,
    first_seen: Instant,
    announced: bool,
    via: String,
    from: String,
    tty: String,
    origin: String,
    cmds: u64,
    leader: i32,
}

struct Tracker {
    ctx: Ctx,
    users: Users,
    procs: HashMap<i32, Proc>,
    sessions: HashMap<u32, Session>,
    max_args: usize,
    last_gc: Instant,
}

fn valid(auid: u32, ses: u32) -> bool {
    auid != NO_UID && ses != NO_UID
}

impl Tracker {
    fn new(ctx: Ctx) -> Tracker {
        let max_args = ctx.cfg.exec.max_args_len;
        Tracker {
            ctx,
            users: Users::new(),
            procs: HashMap::new(),
            sessions: HashMap::new(),
            max_args,
            last_gc: Instant::now(),
        }
    }

    fn to_proc(p: &ProcInfo) -> Proc {
        Proc {
            ppid: p.ppid,
            uid: p.uid,
            euid: p.euid,
            auid: p.auid,
            ses: p.ses,
            start: p.start,
            exe: p.exe.clone(),
            argv: p.argv.clone(),
        }
    }

    /// Carrega os processos que já existem e anuncia as sessões ativas.
    fn scan_existing(&mut self) {
        for pid in procfs::all_pids() {
            if let Some(p) = procfs::read(pid, self.max_args) {
                self.procs.insert(pid, Self::to_proc(&p));
                if valid(p.auid, p.ses) {
                    self.touch_session(&p, true);
                }
            }
        }
        let ids: Vec<u32> = self.sessions.keys().copied().collect();
        for id in ids {
            self.identify(id);
            self.announce(id, "session.active", "sessão já ativa quando o Loger iniciou");
        }
    }

    fn touch_session(&mut self, p: &ProcInfo, quiet: bool) {
        if self.sessions.contains_key(&p.ses) {
            return;
        }
        let origin = self.procs.get(&p.ppid).map(|pp| pp.exe.clone()).unwrap_or_default();
        let user = self.users.name(p.auid);
        self.sessions.insert(
            p.ses,
            Session {
                auid: p.auid,
                user,
                start_ms: now_ms(),
                first_seen: if quiet { Instant::now() - Duration::from_secs(60) } else { Instant::now() },
                announced: false,
                via: String::new(),
                from: String::new(),
                tty: p.tty.clone(),
                origin,
                cmds: 0,
                leader: p.pid,
            },
        );
    }

    /// Descobre se a sessão é SSH e de qual IP, olhando os processos dela.
    fn identify(&mut self, ses: u32) {
        let pids: Vec<i32> = self.procs.iter().filter(|(_, p)| p.ses == ses).map(|(pid, _)| *pid).collect();
        let Some(s) = self.sessions.get_mut(&ses) else { return };
        if !s.from.is_empty() {
            return;
        }
        for pid in &pids {
            if let Some(conn) = procfs::env_var(*pid, "SSH_CONNECTION") {
                let f: Vec<&str> = conn.split_whitespace().collect();
                if f.len() >= 2 {
                    s.via = "ssh".into();
                    s.from = format!("{}:{}", f[0], f[1]);
                    if s.tty.is_empty() {
                        s.tty = procfs::env_var(*pid, "SSH_TTY").unwrap_or_default().trim_start_matches("/dev/").into();
                    }
                    return;
                }
            }
        }
        // Sessões SSH sem shell (sftp interno, ssh -N com túnel) não têm processo com
        // SSH_CONNECTION: o IP sai do socket do próprio sshd.
        for pid in &pids {
            let exe = self.procs.get(pid).map(|p| p.exe.as_str()).unwrap_or("");
            if basename(exe).starts_with("sshd") {
                if let Some(peer) = net::tcp_peer_of(*pid) {
                    s.via = "ssh".into();
                    s.from = peer;
                    return;
                }
            }
        }
    }

    fn announce(&mut self, ses: u32, kind: &str, why: &str) {
        let Some(s) = self.sessions.get_mut(&ses) else { return };
        if s.announced {
            return;
        }
        s.announced = true;
        if s.via.is_empty() {
            s.via = if basename(&s.origin).starts_with("cron") || basename(&s.origin) == "crond" {
                "cron".into()
            } else if s.tty.starts_with("tty") {
                "console".into()
            } else {
                "local".into()
            };
        }
        let msg = match s.via.as_str() {
            "ssh" => format!("{}: login SSH de {} {}", why, s.from, s.tty),
            v => format!("{}: login {} {}", why, v, s.tty),
        };
        let level = if s.via == "cron" { INFO } else { NOTICE };
        self.ctx.send(Ev::new(kind, level, msg.trim_end().to_string()).user(s.user.clone()).data(json!({
            "ses": ses, "auid": s.auid, "via": s.via, "from": s.from, "tty": s.tty, "origin": s.origin,
        })));
    }

    fn on_fork(&mut self, parent: i32, child: i32) {
        let mut p = match self.procs.get(&parent) {
            Some(pp) => pp.clone(),
            None => match procfs::read(child, self.max_args) {
                Some(pi) => Self::to_proc(&pi),
                None => return,
            },
        };
        p.ppid = parent;
        // O login (pam_loginuid) muda o loginuid sem gerar evento, então relê no fork.
        let (auid, ses) = procfs::login_ids(child);
        p.auid = auid;
        p.ses = ses;
        self.procs.insert(child, p);
        if valid(auid, ses) && !self.sessions.contains_key(&ses) {
            if let Some(pi) = procfs::read(child, self.max_args) {
                self.touch_session(&pi, false);
            }
        }
    }

    fn on_exec(&mut self, pid: i32) {
        let info = procfs::read(pid, self.max_args);
        let gone = info.is_none();
        let p = match &info {
            Some(pi) => pi.clone(),
            None => {
                // O processo terminou antes de conseguirmos ler: usa o que sabemos do fork.
                let Some(known) = self.procs.get(&pid) else { return };
                ProcInfo {
                    pid,
                    ppid: known.ppid,
                    uid: known.uid,
                    euid: known.euid,
                    auid: known.auid,
                    ses: known.ses,
                    ..Default::default()
                }
            }
        };
        let parent_exe = self.procs.get(&p.ppid).map(|pp| pp.exe.clone()).unwrap_or_default();
        self.procs.insert(pid, Self::to_proc(&p));

        let in_session = valid(p.auid, p.ses);
        if in_session {
            self.touch_session(&p, false);
            if let Some(s) = self.sessions.get_mut(&p.ses) {
                s.cmds += 1;
                if s.tty.is_empty() {
                    s.tty = p.tty.clone();
                }
            }
            if !self.sessions[&p.ses].announced {
                self.identify(p.ses);
                if !self.sessions[&p.ses].from.is_empty() {
                    self.announce(p.ses, "session.start", "início de sessão");
                }
            }
        }
        let cfg = &self.ctx.cfg.exec;
        if cfg.only_sessions && !in_session {
            return;
        }
        if cfg.ignore_exe.iter().any(|e| *e == p.exe) {
            return;
        }

        let (kind, mut level) = classify(&p);
        let mut tags = vec![];
        if p.exe_deleted {
            tags.push("binario_apagado");
            level = ALERT;
        }
        if gone {
            tags.push("terminou_antes_da_leitura");
        }
        let cmd = if p.argv.is_empty() {
            if gone { "(processo curto demais: argumentos não capturados)".into() } else { p.comm.clone() }
        } else {
            join_argv(&p.argv)
        };
        let user = self.users.name(if in_session { p.auid } else { p.uid });
        let as_user = if p.euid != p.auid && in_session { self.users.name(p.euid) } else { String::new() };
        let msg = if as_user.is_empty() { cmd } else { format!("[como {}] {}", as_user, cmd) };
        self.ctx.send(Ev::new(kind, level, msg).user(user).data(json!({
            "pid": p.pid, "ppid": p.ppid, "uid": p.uid, "euid": p.euid, "auid": p.auid,
            "ses": if in_session { json!(p.ses) } else { json!(null) },
            "tty": p.tty, "exe": p.exe, "cwd": p.cwd, "argv": p.argv, "parent": parent_exe, "tags": tags,
        })));
    }

    fn on_uid(&mut self, pid: i32, ruid: u32, euid: u32) {
        let Some(old) = self.procs.get(&pid).cloned() else { return };
        // Usuário comum (uid real != 0) virando root sem ser um binário setuid-root
        // (sudo, su, passwd...): sinal de exploit de escalada de privilégio.
        if euid == 0 && old.euid != 0 && old.uid != 0 && !setuid_root(pid, &old.exe) {
            let user = self.users.name(if old.auid != NO_UID { old.auid } else { old.uid });
            self.ctx.send(
                Ev::new(
                    "priv.escalation",
                    ALERT,
                    format!("processo {} ({}) virou root sem passar por sudo/su", pid, old.exe),
                )
                .user(user)
                .data(json!({ "pid": pid, "exe": old.exe, "argv": old.argv, "old_uid": old.uid, "old_euid": old.euid, "ses": old.ses })),
            );
        }
        if let Some(p) = self.procs.get_mut(&pid) {
            p.uid = ruid;
            p.euid = euid;
        }
    }

    fn on_ptrace(&mut self, pid: i32, tracer: i32) {
        if tracer == 0 {
            return;
        }
        let target = self.procs.get(&pid).cloned();
        let tr = self.procs.get(&tracer).cloned();
        let auid = tr.as_ref().map(|t| t.auid).unwrap_or(NO_UID);
        if self.ctx.cfg.exec.only_sessions && auid == NO_UID {
            return;
        }
        let user = self.users.name(auid);
        let texe = target.map(|t| t.exe).unwrap_or_default();
        let trexe = tr.map(|t| t.exe).unwrap_or_default();
        self.ctx.send(
            Ev::new("proc.ptrace", WARN, format!("{} (pid {}) se anexou ao processo {} ({})", trexe, tracer, pid, texe))
                .user(user)
                .data(json!({ "pid": pid, "exe": texe, "tracer_pid": tracer, "tracer_exe": trexe })),
        );
    }

    fn on_exit(&mut self, pid: i32) {
        self.procs.remove(&pid);
    }

    /// Roda ~1x por segundo: anuncia sessões pendentes e encerra as que acabaram.
    fn housekeeping(&mut self) {
        let pending: Vec<u32> = self
            .sessions
            .iter()
            .filter(|(_, s)| !s.announced && s.first_seen.elapsed() > Duration::from_secs(2))
            .map(|(id, _)| *id)
            .collect();
        for id in pending {
            self.identify(id);
            self.announce(id, "session.start", "início de sessão");
        }

        // Se o kernel descartou eventos de exit, remove processos que já não existem.
        if self.last_gc.elapsed() > Duration::from_secs(30) {
            self.last_gc = Instant::now();
            self.procs.retain(|pid, p| {
                procfs::read_text_start(*pid).map(|s| s == p.start || p.start == 0).unwrap_or(false)
            });
        }

        let alive: std::collections::HashSet<u32> = self.procs.values().map(|p| p.ses).collect();
        let ended: Vec<u32> = self.sessions.keys().filter(|id| !alive.contains(id)).copied().collect();
        for id in ended {
            // Sessão que terminou antes de ser anunciada (ex: cron rápido) também é registrada.
            self.identify(id);
            let s = self.sessions.remove(&id).unwrap();
            let secs = now_ms().saturating_sub(s.start_ms) / 1000;
            let via = if s.via.is_empty() { "local".to_string() } else { s.via.clone() };
            let from = if s.from.is_empty() { String::new() } else { format!(" de {}", s.from) };
            self.ctx.send(
                Ev::new(
                    "session.end",
                    if via == "cron" { INFO } else { NOTICE },
                    format!("fim de sessão {}{} — duração {}, {} comandos", via, from, fmt_dur(secs), s.cmds),
                )
                .user(s.user)
                .data(json!({ "ses": id, "auid": s.auid, "via": via, "from": s.from, "tty": s.tty, "duration_secs": secs, "commands": s.cmds, "leader": s.leader })),
            );
        }
    }
}

/// O executável atual do processo é setuid root? (No exec de um binário setuid o kernel
/// avisa a troca de uid antes do próprio exec, então lê o exe direto de /proc.)
fn setuid_root(pid: i32, known_exe: &str) -> bool {
    use std::os::unix::fs::MetadataExt;
    let exe = std::fs::read_link(format!("/proc/{}/exe", pid))
        .map(|p| p.to_string_lossy().trim_end_matches(" (deleted)").to_string())
        .unwrap_or_else(|_| known_exe.to_string());
    std::fs::metadata(&exe).map(|m| m.uid() == 0 && m.mode() & 0o4000 != 0).unwrap_or(false)
}

fn fmt_dur(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m{}s", secs / 60, secs % 60)
    } else {
        format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
    }
}

/// Classifica o comando pelo nome do binário para facilitar filtros.
fn classify(p: &ProcInfo) -> (&'static str, &'static str) {
    let exe = if p.exe.is_empty() { p.argv.first().map(|s| s.as_str()).unwrap_or("") } else { &p.exe };
    for dir in ["/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/"] {
        if exe.starts_with(dir) {
            return ("exec.suspicious", ALERT);
        }
    }
    // Testa o nome real do binário e o nome usado para chamá-lo (nc -> nc.openbsd).
    let argv0 = p.argv.first().map(|a| basename(a)).unwrap_or("");
    let by_exe = classify_name(basename(exe));
    if by_exe.0 != "exec" { by_exe } else { classify_name(argv0) }
}

fn classify_name(name: &str) -> (&'static str, &'static str) {
    match name {
        "sudo" | "su" | "pkexec" | "doas" | "runuser" | "sudoedit" => ("priv.cmd", NOTICE),
        "useradd" | "userdel" | "usermod" | "adduser" | "deluser" | "passwd" | "chpasswd" | "chage"
        | "groupadd" | "groupdel" | "groupmod" | "gpasswd" | "addgroup" | "delgroup" | "visudo" | "vipw" => {
            ("account.cmd", WARN)
        }
        "iptables" | "ip6tables" | "iptables-restore" | "ip6tables-restore" | "nft" | "ufw" | "firewall-cmd" => {
            ("firewall.cmd", WARN)
        }
        "insmod" | "rmmod" | "modprobe" => ("kernel.module_cmd", WARN),
        "crontab" | "at" | "batch" => ("cron.cmd", NOTICE),
        "systemctl" | "service" | "rc-service" | "update-rc.d" | "chkconfig" => ("service.cmd", INFO),
        "mount" | "umount" => ("mount.cmd", NOTICE),
        "scp" | "sftp-server" | "rsync" => ("ssh.transfer", NOTICE),
        "shutdown" | "reboot" | "halt" | "poweroff" | "init" | "telinit" => ("system.power_cmd", WARN),
        "nc" | "ncat" | "netcat" | "socat" | "nmap" | "tcpdump" => ("exec.net_tool", WARN),
        "history" | "unset" | "shred" | "wipe" => ("exec.antiforensics", WARN),
        _ => ("exec", INFO),
    }
}

// ---------------- proc connector (netlink) ----------------

const NETLINK_CONNECTOR: i32 = 11;
const CN_IDX_PROC: u32 = 1;
const CN_VAL_PROC: u32 = 1;
const PROC_CN_MCAST_LISTEN: u32 = 1;
const EV_FORK: u32 = 0x1;
const EV_EXEC: u32 = 0x2;
const EV_UID: u32 = 0x4;
const EV_PTRACE: u32 = 0x100;
const EV_EXIT: u32 = 0x8000_0000;

struct Conn(i32);

impl Drop for Conn {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

fn open_connector() -> io::Result<Conn> {
    unsafe {
        let fd = libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, NETLINK_CONNECTOR);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let conn = Conn(fd);
        // Buffer grande para aguentar rajadas (ex: compilação, fork bomb).
        let sz: libc::c_int = 8 << 20;
        let p = &sz as *const _ as *const libc::c_void;
        let l = std::mem::size_of::<libc::c_int>() as u32;
        if libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUFFORCE, p, l) != 0 {
            libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, p, l);
        }
        let mut sa: libc::sockaddr_nl = std::mem::zeroed();
        sa.nl_family = libc::AF_NETLINK as u16;
        sa.nl_groups = CN_IDX_PROC;
        if libc::bind(fd, &sa as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_nl>() as u32) != 0 {
            return Err(io::Error::last_os_error());
        }
        // nlmsghdr (16) + cn_msg (20) + op (4)
        let mut msg = [0u8; 40];
        msg[0..4].copy_from_slice(&40u32.to_ne_bytes());
        msg[4..6].copy_from_slice(&(libc::NLMSG_DONE as u16).to_ne_bytes());
        msg[12..16].copy_from_slice(&(libc::getpid() as u32).to_ne_bytes());
        msg[16..20].copy_from_slice(&CN_IDX_PROC.to_ne_bytes());
        msg[20..24].copy_from_slice(&CN_VAL_PROC.to_ne_bytes());
        msg[32..34].copy_from_slice(&4u16.to_ne_bytes());
        msg[36..40].copy_from_slice(&PROC_CN_MCAST_LISTEN.to_ne_bytes());
        if libc::send(fd, msg.as_ptr() as *const libc::c_void, msg.len(), 0) < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(conn)
    }
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    b.get(off..off + 4).map(|s| u32::from_ne_bytes(s.try_into().unwrap())).unwrap_or(0)
}

fn run_connector(t: &mut Tracker, conn: Conn) {
    let mut buf = vec![0u8; 16 * 1024];
    let mut lost: u64 = 0;
    let mut last_lost_report = Instant::now();
    let mut last_hk = Instant::now();
    loop {
        let mut pfd = libc::pollfd { fd: conn.0, events: libc::POLLIN, revents: 0 };
        let ready = unsafe { libc::poll(&mut pfd, 1, 1000) };
        if ready > 0 {
            let n = unsafe { libc::recv(conn.0, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ENOBUFS) {
                    lost += 1;
                }
            } else {
                handle_datagram(t, &buf[..n as usize]);
            }
        }
        if lost > 0 && last_lost_report.elapsed() > Duration::from_secs(10) {
            t.ctx.send(Ev::new(
                "loger.events_lost",
                WARN,
                format!("o kernel descartou eventos de processo {} vez(es) por excesso de volume", lost),
            ));
            lost = 0;
            last_lost_report = Instant::now();
        }
        if last_hk.elapsed() >= Duration::from_secs(1) {
            t.housekeeping();
            last_hk = Instant::now();
        }
    }
}

fn handle_datagram(t: &mut Tracker, buf: &[u8]) {
    let mut off = 0;
    while off + 16 <= buf.len() {
        let len = u32_at(buf, off) as usize;
        if len < 16 || off + len > buf.len() {
            break;
        }
        // payload = cn_msg (20 bytes) + proc_event; dados do evento começam em +16 do proc_event
        let ev = &buf[off + 16 + 20..off + len];
        let what = u32_at(ev, 0);
        let d = 16;
        let a = u32_at(ev, d) as i32;
        let b = u32_at(ev, d + 4) as i32;
        match what {
            EV_FORK => {
                let child_pid = u32_at(ev, d + 8) as i32;
                let child_tgid = u32_at(ev, d + 12) as i32;
                if child_pid == child_tgid {
                    t.on_fork(b, child_tgid);
                }
            }
            EV_EXEC if a == b => t.on_exec(b),
            EV_UID if a == b => t.on_uid(b, u32_at(ev, d + 8), u32_at(ev, d + 12)),
            EV_PTRACE => t.on_ptrace(b, u32_at(ev, d + 12) as i32),
            EV_EXIT if a == b => t.on_exit(b),
            _ => {}
        }
        off += (len + 3) & !3;
    }
}

// ---------------- fallback: varredura de /proc ----------------

fn run_polling(t: &mut Tracker) {
    let interval = Duration::from_millis(t.ctx.cfg.exec.poll_interval_ms.max(100));
    loop {
        std::thread::sleep(interval);
        let pids = procfs::all_pids();
        let current: std::collections::HashSet<i32> = pids.iter().copied().collect();
        for pid in pids {
            let start = procfs::read_text_start(pid);
            let known = t.procs.get(&pid).map(|p| Some(p.start) == start).unwrap_or(false);
            if !known {
                t.procs.remove(&pid);
                t.on_exec(pid);
            }
        }
        let gone: Vec<i32> = t.procs.keys().filter(|p| !current.contains(p)).copied().collect();
        for pid in gone {
            t.on_exit(pid);
        }
        t.housekeeping();
    }
}

pub fn run(ctx: Ctx) {
    let mut t = Tracker::new(ctx.clone());
    // LOGER_FORCE_POLL=1 força o modo de varredura (útil para testar o fallback).
    let conn = if std::env::var_os("LOGER_FORCE_POLL").is_some() {
        Err(io::Error::other("desativado por LOGER_FORCE_POLL"))
    } else {
        open_connector()
    };
    match conn {
        Ok(conn) => {
            ctx.send(Ev::new("loger.collector", INFO, "comandos: proc connector do kernel ativo (tempo real)"));
            t.scan_existing();
            run_connector(&mut t, conn);
        }
        Err(e) => {
            ctx.send(Ev::new(
                "loger.collector",
                WARN,
                format!("comandos: proc connector indisponível ({}), usando varredura de /proc — processos muito curtos podem escapar", e),
            ));
            t.scan_existing();
            run_polling(&mut t);
        }
    }
}
