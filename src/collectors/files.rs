//! Arquivos sensíveis via inotify (existe em todo Linux desde 2.6.13).
//!
//! Vigia diretórios (não arquivos soltos), para pegar editores que salvam com
//! "grava temporário + rename" e arquivos que ainda não existem (ex: /etc/ld.so.preload).
//! Além de "mudou", analisa o conteúdo de alguns arquivos: usuários criados/removidos,
//! membros de grupos e chaves SSH adicionadas/removidas.

use super::Ctx;
use crate::event::{Ev, ALERT, INFO, NOTICE, WARN};
use crate::users;
use crate::util::{self, read_text};
use serde_json::json;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::ffi::CString;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const MASK_DIR: u32 = libc::IN_CLOSE_WRITE | libc::IN_ATTRIB | libc::IN_CREATE | libc::IN_DELETE
    | libc::IN_MOVED_FROM | libc::IN_MOVED_TO | libc::IN_DELETE_SELF | libc::IN_MOVE_SELF;
const MASK_READ: u32 = libc::IN_OPEN;
const MAX_CONTENT: usize = 1024 * 1024;

#[derive(Clone, Copy, PartialEq)]
enum WatchKind {
    Dir,
    Read,
}

struct Pending {
    actions: BTreeSet<&'static str>,
    last: Instant,
}

struct Watcher {
    ctx: Ctx,
    fd: i32,
    wds: HashMap<i32, (PathBuf, WatchKind)>,
    watched_dirs: HashSet<PathBuf>,
    /// Arquivos-alvo (o pai é vigiado) e diretórios-alvo (vigiados com subdiretórios).
    file_targets: HashSet<PathBuf>,
    dir_targets: Vec<PathBuf>,
    read_targets: HashSet<PathBuf>,
    /// Último estado conhecido de cada arquivo: hash + metadados + conteúdo (para diff).
    snap: HashMap<PathBuf, Snap>,
    pending: HashMap<PathBuf, Pending>,
}

#[derive(Clone, PartialEq)]
struct Snap {
    hash: String,
    mode: u32,
    uid: u32,
    gid: u32,
    content: Option<String>,
}

fn snapshot(p: &Path) -> Option<Snap> {
    let md = std::fs::symlink_metadata(p).ok()?;
    if md.is_dir() {
        return None;
    }
    let content = if md.len() as usize <= MAX_CONTENT { read_text(p, MAX_CONTENT) } else { None };
    Some(Snap {
        hash: content.as_ref().map(|c| util::sha256_hex(c.as_bytes())).unwrap_or_default(),
        mode: md.mode() & 0o7777,
        uid: md.uid(),
        gid: md.gid(),
        content: if wants_content(p) { content } else { None },
    })
}

fn wants_content(p: &Path) -> bool {
    let n = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
    matches!(p.to_str(), Some("/etc/passwd") | Some("/etc/group")) || n.starts_with("authorized_keys")
}

fn level_for(p: &Path) -> &'static str {
    let s = p.to_string_lossy();
    let n = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if n.starts_with("authorized_keys") || s.starts_with("/etc/sudoers") || s.starts_with("/etc/shadow")
        || s.starts_with("/etc/passwd") || s.starts_with("/etc/ld.so.preload") || s.starts_with("/etc/pam.d")
        || s.contains("cron") || s.starts_with("/etc/systemd/system") || s.starts_with("/etc/ssh/sshd_config")
    {
        ALERT
    } else {
        WARN
    }
}

impl Watcher {
    fn add_watch(&mut self, path: &Path, kind: WatchKind) -> bool {
        if kind == WatchKind::Dir && self.watched_dirs.contains(path) {
            return true;
        }
        let Ok(c) = CString::new(path.as_os_str().as_encoded_bytes()) else { return false };
        let mask = if kind == WatchKind::Dir { MASK_DIR | libc::IN_ONLYDIR } else { MASK_READ };
        let wd = unsafe { libc::inotify_add_watch(self.fd, c.as_ptr(), mask) };
        if wd < 0 {
            return false;
        }
        self.wds.insert(wd, (path.to_path_buf(), kind));
        if kind == WatchKind::Dir {
            self.watched_dirs.insert(path.to_path_buf());
        }
        true
    }

    /// Vigia `dir`; se não existir, vigia o ancestral mais próximo que existe para ver a criação.
    fn ensure_dir(&mut self, dir: &Path) {
        let mut d = dir.to_path_buf();
        loop {
            if d.is_dir() && self.add_watch(&d, WatchKind::Dir) {
                return;
            }
            if !d.pop() {
                return;
            }
        }
    }

    fn watch_tree(&mut self, dir: &Path, depth: u32) {
        self.ensure_dir(dir);
        if depth == 0 || !dir.is_dir() {
            return;
        }
        for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let p = e.path();
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                self.watch_tree(&p, depth - 1);
            } else if let Some(s) = snapshot(&p) {
                self.snap.insert(p, s);
            }
        }
    }

    fn setup(&mut self) {
        let cfg = self.ctx.cfg.files.clone();
        for t in &cfg.watch {
            let p = PathBuf::from(t);
            if p.is_dir() {
                self.dir_targets.push(p.clone());
                self.watch_tree(&p, 2);
            } else if t.ends_with('/') || matches!(p.file_name().and_then(|n| n.to_str()), Some(n) if n.ends_with(".d") || n == "cron" || n == "system") {
                // Diretório que ainda não existe.
                self.dir_targets.push(p.clone());
                self.ensure_dir(&p);
            } else {
                self.file_targets.insert(p.clone());
                if let Some(s) = snapshot(&p) {
                    self.snap.insert(p.clone(), s);
                }
                self.ensure_dir(p.parent().unwrap_or(Path::new("/")));
            }
        }
        if cfg.authorized_keys {
            self.setup_keys();
        }
        for t in &cfg.watch_reads {
            let p = PathBuf::from(t);
            self.read_targets.insert(p.clone());
            self.add_watch(&p, WatchKind::Read);
        }
    }

    fn setup_keys(&mut self) {
        let mut homes: Vec<PathBuf> = users::entries()
            .into_iter()
            .filter(|e| (e.uid == 0 || e.uid >= 1000) && e.home.is_dir() && !e.shell.ends_with("nologin") && !e.shell.ends_with("false"))
            .map(|e| e.home)
            .collect();
        homes.push(PathBuf::from("/root"));
        homes.sort();
        homes.dedup();
        for h in homes {
            for name in ["authorized_keys", "authorized_keys2"] {
                let p = h.join(".ssh").join(name);
                if self.file_targets.insert(p.clone()) {
                    if let Some(s) = snapshot(&p) {
                        self.snap.insert(p.clone(), s);
                    }
                }
            }
            self.ensure_dir(&h.join(".ssh"));
        }
    }

    fn relevant(&self, p: &Path) -> bool {
        self.file_targets.contains(p) || self.dir_targets.iter().any(|d| p.starts_with(d))
    }

    fn handle(&mut self, wd: i32, mask: u32, name: &str) {
        let Some((base, kind)) = self.wds.get(&wd).cloned() else { return };
        if mask & libc::IN_IGNORED != 0 {
            self.wds.remove(&wd);
            self.watched_dirs.remove(&base);
            // O diretório sumiu ou foi trocado: vigia de novo (ou o ancestral) para pegar a recriação.
            if kind == WatchKind::Dir {
                self.ensure_dir(&base);
            } else if self.read_targets.contains(&base) {
                std::thread::sleep(Duration::from_millis(50));
                self.add_watch(&base, WatchKind::Read);
            }
            return;
        }
        if kind == WatchKind::Read {
            if mask & libc::IN_OPEN != 0 {
                self.ctx.send(Ev::new("file.read", NOTICE, format!("{} foi aberto para leitura", base.display()))
                    .data(json!({ "path": base })));
            }
            return;
        }
        let path = if name.is_empty() { base.clone() } else { base.join(name) };
        let is_dir = mask & libc::IN_ISDIR != 0;

        // Diretório novo: pode ser um alvo (ou caminho até um alvo) que ainda não existia.
        if is_dir && mask & (libc::IN_CREATE | libc::IN_MOVED_TO) != 0 {
            if self.dir_targets.iter().any(|d| path.starts_with(d)) {
                self.watch_tree(&path, 1);
            }
            let below: Vec<PathBuf> = self
                .dir_targets
                .iter()
                .cloned()
                .chain(self.file_targets.iter().filter_map(|f| f.parent().map(Path::to_path_buf)))
                .filter(|t| t.starts_with(&path))
                .collect();
            for t in below {
                self.ensure_dir(&t);
            }
            // Arquivos-alvo criados antes de a vigilância do diretório novo começar.
            let created: Vec<PathBuf> = self
                .file_targets
                .iter()
                .filter(|f| f.starts_with(&path) && f.exists() && !self.snap.contains_key(*f))
                .cloned()
                .collect();
            for f in created {
                self.pending.insert(f, Pending { actions: BTreeSet::from(["criado"]), last: Instant::now() });
            }
        }
        if !self.relevant(&path) {
            return;
        }
        let action = if mask & (libc::IN_CREATE | libc::IN_MOVED_TO) != 0 {
            "criado"
        } else if mask & (libc::IN_DELETE | libc::IN_MOVED_FROM) != 0 {
            "removido"
        } else if mask & libc::IN_CLOSE_WRITE != 0 {
            "modificado"
        } else if mask & libc::IN_ATTRIB != 0 {
            "permissões"
        } else {
            return;
        };
        let p = self.pending.entry(path).or_insert(Pending { actions: BTreeSet::new(), last: Instant::now() });
        p.actions.insert(action);
        p.last = Instant::now();
    }

    /// Agrupa rajadas de eventos (um editor gera vários) e emite um evento por arquivo.
    fn flush(&mut self, force: bool) {
        let ready: Vec<PathBuf> = self
            .pending
            .iter()
            .filter(|(_, p)| force || p.last.elapsed() > Duration::from_millis(700))
            .map(|(k, _)| k.clone())
            .collect();
        for path in ready {
            let pend = self.pending.remove(&path).unwrap();
            let old = self.snap.get(&path).cloned();
            let new = snapshot(&path);
            if old == new && old.is_some() {
                continue; // nada mudou de fato (ex: só abriram e fecharam)
            }
            match &new {
                Some(s) => self.snap.insert(path.clone(), s.clone()),
                None => self.snap.remove(&path),
            };
            self.report(&path, &pend.actions, old.as_ref(), new.as_ref());
            if path == Path::new("/etc/passwd") && self.ctx.cfg.files.authorized_keys {
                self.setup_keys(); // usuário novo -> vigia o authorized_keys dele
            }
        }
    }

    fn report(&mut self, path: &Path, actions: &BTreeSet<&str>, old: Option<&Snap>, new: Option<&Snap>) {
        let (kind, verb) = match (old, new) {
            (None, Some(_)) => ("file.created", "criado"),
            (Some(_), None) => ("file.deleted", "removido"),
            (Some(o), Some(n)) if o.hash == n.hash => ("file.perm", "teve permissões/dono alterados"),
            _ => ("file.modified", "modificado"),
        };
        let level = level_for(path);
        let mut details = vec![];
        if let (Some(o), Some(n)) = (old, new) {
            if o.mode != n.mode {
                details.push(format!("modo {:o} -> {:o}", o.mode, n.mode));
            }
            if o.uid != n.uid || o.gid != n.gid {
                details.push(format!("dono {}:{} -> {}:{}", o.uid, o.gid, n.uid, n.gid));
            }
        }
        let msg = if details.is_empty() {
            format!("{} {}", path.display(), verb)
        } else {
            format!("{} {} ({})", path.display(), verb, details.join(", "))
        };
        self.ctx.send(Ev::new(kind, level, msg).data(json!({
            "path": path, "actions": actions,
            "old_sha256": old.map(|s| s.hash.as_str()), "new_sha256": new.map(|s| s.hash.as_str()),
            "mode": new.map(|s| format!("{:o}", s.mode)), "uid": new.map(|s| s.uid), "gid": new.map(|s| s.gid),
        })));

        let oc = old.and_then(|s| s.content.as_deref()).unwrap_or("");
        let nc = new.and_then(|s| s.content.as_deref()).unwrap_or("");
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path == Path::new("/etc/passwd") {
            self.diff_accounts(oc, nc);
        } else if path == Path::new("/etc/group") {
            self.diff_groups(oc, nc);
        } else if name.starts_with("authorized_keys") {
            self.diff_keys(path, oc, nc);
        }
    }

    fn diff_accounts(&self, old: &str, new: &str) {
        let parse = |t: &str| -> HashMap<String, String> {
            t.lines().filter_map(|l| Some((l.split(':').next()?.to_string(), l.to_string()))).collect()
        };
        let (o, n) = (parse(old), parse(new));
        for (name, line) in &n {
            let f: Vec<&str> = line.split(':').collect();
            match o.get(name) {
                None => self.ctx.send(Ev::new("account.user_added", ALERT, format!("usuário criado: {} (uid {}, shell {})", name, f.get(2).unwrap_or(&"?"), f.get(6).unwrap_or(&"?")))
                    .user(name.clone()).data(json!({ "entry": line }))),
                Some(old_line) if old_line != line => {
                    let of: Vec<&str> = old_line.split(':').collect();
                    let level = if f.get(2) == Some(&"0") && of.get(2) != Some(&"0") { ALERT } else { WARN };
                    self.ctx.send(Ev::new("account.user_changed", level, format!("usuário alterado: {}: {} -> {}", name, old_line, line))
                        .user(name.clone()).data(json!({ "old": old_line, "new": line })));
                }
                _ => {}
            }
        }
        for name in o.keys().filter(|k| !n.contains_key(*k)) {
            self.ctx.send(Ev::new("account.user_removed", WARN, format!("usuário removido: {}", name)).user(name.clone()));
        }
    }

    fn diff_groups(&self, old: &str, new: &str) {
        let parse = |t: &str| -> HashMap<String, BTreeSet<String>> {
            t.lines()
                .filter_map(|l| {
                    let f: Vec<&str> = l.split(':').collect();
                    let members = f.get(3)?.split(',').filter(|s| !s.is_empty()).map(String::from).collect();
                    Some((f[0].to_string(), members))
                })
                .collect()
        };
        let (o, n) = (parse(old), parse(new));
        const PRIV: &[&str] = &["root", "sudo", "wheel", "admin", "adm", "docker", "lxd", "disk", "shadow"];
        for (g, members) in &n {
            let before = o.get(g).cloned().unwrap_or_default();
            if !o.contains_key(g) {
                self.ctx.send(Ev::new("account.group_added", NOTICE, format!("grupo criado: {}", g)));
            }
            for m in members.difference(&before) {
                let level = if PRIV.contains(&g.as_str()) { ALERT } else { NOTICE };
                self.ctx.send(Ev::new("account.group_member_added", level, format!("{} adicionado ao grupo {}", m, g))
                    .user(m.clone()).data(json!({ "group": g })));
            }
            for m in before.difference(members) {
                self.ctx.send(Ev::new("account.group_member_removed", NOTICE, format!("{} removido do grupo {}", m, g))
                    .user(m.clone()).data(json!({ "group": g })));
            }
        }
        for g in o.keys().filter(|k| !n.contains_key(*k)) {
            self.ctx.send(Ev::new("account.group_removed", NOTICE, format!("grupo removido: {}", g)));
        }
    }

    fn diff_keys(&self, path: &Path, old: &str, new: &str) {
        let keys = |t: &str| -> BTreeSet<String> {
            t.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).map(String::from).collect()
        };
        let (o, n) = (keys(old), keys(new));
        let owner = path.parent().and_then(|p| p.parent()).and_then(|h| h.file_name()).and_then(|n| n.to_str()).unwrap_or("").to_string();
        let describe = |line: &str| -> (String, String, String) {
            // [opções] tipo base64 [comentário]
            let parts: Vec<&str> = line.split_whitespace().collect();
            let i = parts.iter().position(|p| p.starts_with("ssh-") || p.starts_with("ecdsa-") || p.starts_with("sk-")).unwrap_or(0);
            let ktype = parts.get(i).copied().unwrap_or("?").to_string();
            let fp = parts.get(i + 1).and_then(|k| util::ssh_fingerprint(k)).unwrap_or_default();
            let comment = parts.get(i + 2..).map(|c| c.join(" ")).unwrap_or_default();
            (ktype, fp, comment)
        };
        for k in n.difference(&o) {
            let (t, fp, c) = describe(k);
            self.ctx.send(Ev::new("ssh.key_added", ALERT, format!("chave SSH ADICIONADA em {}: {} {} {}", path.display(), t, fp, c))
                .user(owner.clone()).data(json!({ "path": path, "type": t, "fingerprint": fp, "comment": c })));
        }
        for k in o.difference(&n) {
            let (t, fp, c) = describe(k);
            self.ctx.send(Ev::new("ssh.key_removed", WARN, format!("chave SSH removida de {}: {} {} {}", path.display(), t, fp, c))
                .user(owner.clone()).data(json!({ "path": path, "type": t, "fingerprint": fp, "comment": c })));
        }
    }
}

pub fn run(ctx: Ctx) {
    let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
    if fd < 0 {
        ctx.send(Ev::new("loger.collector", WARN, format!("arquivos: inotify indisponível ({})", std::io::Error::last_os_error())));
        return;
    }
    let mut w = Watcher {
        ctx: ctx.clone(),
        fd,
        wds: HashMap::new(),
        watched_dirs: HashSet::new(),
        file_targets: HashSet::new(),
        dir_targets: vec![],
        read_targets: HashSet::new(),
        snap: HashMap::new(),
        pending: HashMap::new(),
    };
    w.setup();
    ctx.send(Ev::new("loger.collector", INFO, format!("arquivos: vigiando {} diretórios", w.watched_dirs.len())));

    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        let timeout = if w.pending.is_empty() { 5000 } else { 300 };
        if unsafe { libc::poll(&mut pfd, 1, timeout) } > 0 {
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n > 0 {
                let mut off = 0usize;
                let n = n as usize;
                // struct inotify_event { int wd; u32 mask; u32 cookie; u32 len; char name[len]; }
                while off + 16 <= n {
                    let wd = i32::from_ne_bytes(buf[off..off + 4].try_into().unwrap());
                    let mask = u32::from_ne_bytes(buf[off + 4..off + 8].try_into().unwrap());
                    let len = u32::from_ne_bytes(buf[off + 12..off + 16].try_into().unwrap()) as usize;
                    let raw = &buf[off + 16..(off + 16 + len).min(n)];
                    let name = String::from_utf8_lossy(raw.split(|&b| b == 0).next().unwrap_or(&[])).into_owned();
                    if mask & libc::IN_Q_OVERFLOW != 0 {
                        ctx.send(Ev::new("loger.events_lost", WARN, "inotify: fila estourou, eventos de arquivo perdidos"));
                    } else {
                        w.handle(wd, mask, &name);
                    }
                    off += 16 + len;
                }
            }
        }
        w.flush(false);
    }
}
