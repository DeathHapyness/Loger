pub mod auth;
pub mod exec;
pub mod files;
pub mod net;
pub mod system;

use crate::config::Config;
use crate::event::Ev;
use std::sync::mpsc::SyncSender;
use std::sync::Arc;

/// O que cada coletor recebe: canal para mandar eventos e a configuração.
#[derive(Clone)]
pub struct Ctx {
    pub tx: SyncSender<Ev>,
    pub cfg: Arc<Config>,
}

impl Ctx {
    pub fn send(&self, ev: Ev) {
        let _ = self.tx.send(ev);
    }
}

pub fn start_all(ctx: &Ctx) {
    let c = &ctx.cfg;
    let list: [(&str, bool, fn(Ctx)); 5] = [
        ("exec", c.exec.enabled, exec::run),
        ("auth", c.auth.enabled, auth::run),
        ("files", c.files.enabled, files::run),
        ("net", c.net.enabled, net::run),
        ("system", c.system.enabled, system::run),
    ];
    for (name, enabled, f) in list {
        if enabled {
            let ctx = ctx.clone();
            std::thread::Builder::new()
                .name(name.into())
                .stack_size(256 * 1024)
                .spawn(move || f(ctx))
                .expect("falha ao criar thread");
        }
    }
}
