//! Sistema: mudança de hora, módulos do kernel e montagens.

use super::Ctx;
use crate::event::{Ev, ALERT, INFO, NOTICE, WARN};
use crate::util::{now_ms, read_text};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

fn modules() -> BTreeSet<String> {
    read_text("/proc/modules", 1 << 20)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split_whitespace().next().map(String::from))
        .collect()
}

fn mounts(ignore: &[String]) -> BTreeMap<String, (String, String)> {
    read_text("/proc/self/mounts", 1 << 20)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let mnt = f.get(1)?.replace("\\040", " ");
            if ignore.iter().any(|i| mnt.starts_with(i.as_str())) {
                return None;
            }
            Some((mnt, (f.first()?.to_string(), f.get(2)?.to_string())))
        })
        .collect()
}

pub fn run(ctx: Ctx) {
    let cfg = ctx.cfg.system.clone();
    if cfg.clock {
        let c = ctx.clone();
        std::thread::spawn(move || clock(c));
    }
    let mut mods = modules();
    let mut mnts = mounts(&cfg.ignore_mounts);
    loop {
        std::thread::sleep(Duration::from_secs(3));
        if cfg.modules {
            let now = modules();
            for m in now.difference(&mods) {
                ctx.send(Ev::new("kernel.module_loaded", WARN, format!("módulo do kernel carregado: {}", m)).data(json!({ "module": m })));
            }
            for m in mods.difference(&now) {
                ctx.send(Ev::new("kernel.module_unloaded", NOTICE, format!("módulo do kernel removido: {}", m)).data(json!({ "module": m })));
            }
            mods = now;
        }
        if cfg.mounts {
            let now = mounts(&cfg.ignore_mounts);
            for (mnt, (src, fs)) in &now {
                if mnts.get(mnt) != Some(&(src.clone(), fs.clone())) {
                    ctx.send(Ev::new("mount.added", NOTICE, format!("{} ({}) montado em {}", src, fs, mnt))
                        .data(json!({ "source": src, "fstype": fs, "mountpoint": mnt })));
                }
            }
            for (mnt, (src, fs)) in mnts.iter().filter(|(k, _)| !now.contains_key(*k)) {
                ctx.send(Ev::new("mount.removed", INFO, format!("{} desmontado de {}", src, mnt))
                    .data(json!({ "source": src, "fstype": fs, "mountpoint": mnt })));
            }
            mnts = now;
        }
    }
}

/// Usa um timerfd com TFD_TIMER_CANCEL_ON_SET: o kernel acorda a thread sempre que alguém
/// ajusta o relógio do sistema (date -s, settimeofday, clock_settime).
fn clock(ctx: Ctx) {
    const TFD_TIMER_ABSTIME: i32 = 1;
    const TFD_TIMER_CANCEL_ON_SET: i32 = 2;
    let fd = unsafe { libc::timerfd_create(libc::CLOCK_REALTIME, libc::TFD_CLOEXEC) };
    if fd < 0 {
        return;
    }
    let offset = || {
        let mut mono: libc::timespec = unsafe { std::mem::zeroed() };
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut mono) };
        now_ms() as i64 - (mono.tv_sec as i64 * 1000 + mono.tv_nsec as i64 / 1_000_000)
    };
    loop {
        let base = offset();
        let mut spec: libc::itimerspec = unsafe { std::mem::zeroed() };
        spec.it_value.tv_sec = (now_ms() / 1000 + 10 * 365 * 86400) as _;
        if unsafe { libc::timerfd_settime(fd, TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET, &spec, std::ptr::null_mut()) } != 0 {
            return;
        }
        let mut buf = [0u8; 8];
        let r = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, 8) };
        if r < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECANCELED) {
            let delta = (offset() - base) / 1000;
            if delta.abs() >= 2 {
                let level = if delta.abs() > 300 { ALERT } else { WARN };
                let dir = if delta > 0 { "adiantado" } else { "atrasado" };
                ctx.send(Ev::new("system.clock_changed", level, format!("relógio do sistema {} em {}s", dir, delta.abs()))
                    .data(json!({ "delta_secs": delta })));
            }
        }
    }
}
