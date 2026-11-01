//! Tradução uid -> nome lendo /etc/passwd direto (sem NSS/libc), com recarga automática.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

pub const NO_UID: u32 = u32::MAX;

pub struct Users {
    names: HashMap<u32, String>,
    mtime: Option<SystemTime>,
    checked: Instant,
}

impl Users {
    pub fn new() -> Users {
        let mut u = Users { names: HashMap::new(), mtime: None, checked: Instant::now() };
        u.reload();
        u
    }

    fn reload(&mut self) {
        self.mtime = std::fs::metadata("/etc/passwd").and_then(|m| m.modified()).ok();
        self.names = entries().into_iter().map(|e| (e.uid, e.name)).collect();
    }

    pub fn name(&mut self, uid: u32) -> String {
        if uid == NO_UID {
            return String::new();
        }
        if self.checked.elapsed() > Duration::from_secs(5) {
            self.checked = Instant::now();
            let m = std::fs::metadata("/etc/passwd").and_then(|m| m.modified()).ok();
            if m != self.mtime {
                self.reload();
            }
        }
        self.names.get(&uid).cloned().unwrap_or_else(|| format!("uid:{}", uid))
    }
}

pub struct Entry {
    pub name: String,
    pub uid: u32,
    pub home: PathBuf,
    pub shell: String,
}

pub fn entries() -> Vec<Entry> {
    let text = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() < 7 {
                return None;
            }
            Some(Entry {
                name: f[0].to_string(),
                uid: f[2].parse().ok()?,
                home: PathBuf::from(f[5]),
                shell: f[6].to_string(),
            })
        })
        .collect()
}
