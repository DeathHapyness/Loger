mod collectors;
mod config;
mod event;
mod procfs;
mod remote;
mod show;
mod store;
mod users;
mod util;

use config::Config;
use event::{Ev, INFO, WARN};
use std::path::PathBuf;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

const HELP: &str = "loger — auditoria leve para servidores Linux

USO:
  loger daemon   [-c CONFIG]          coleta eventos (rodar como root, normalmente via systemd)
  loger show     [-d DIR] [filtros]   mostra os eventos
  loger verify   [-d DIR]             confere se os logs foram alterados ou apagados
  loger receive  [-c CONFIG]          recebe logs de outros servidores (envio remoto)
  loger keygen                        gera a chave para o envio remoto
  loger config                        imprime uma configuração de exemplo comentada
  loger version

FILTROS DO show:
  -k, --kind TIPO     ex: ssh, session, exec, priv, file, account, net, system (vírgula p/ vários)
  -u, --user NOME     usuário que fez o login (mesmo depois de sudo/su)
  -s, --since QUANDO  30m, 2h, 7d ou \"2026-10-04 13:00\"
      --until QUANDO
  -l, --level NIVEL   info, notice, warn, alert (mínimo)
  -g, --grep TEXTO
      --ses N         tudo de uma sessão de login
  -n N                só os últimos N
  -f, --follow        acompanha em tempo real
      --json          saída JSON (uma linha por evento)

Config padrão: /etc/loger/loger.toml (opcional)
";

static STOP: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_signal(sig: libc::c_int) {
    STOP.store(sig, Ordering::SeqCst);
}

fn opt(args: &[String], short: &str, long: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == short || w[0] == long).map(|w| w[1].clone())
}

fn load_config(args: &[String]) -> Config {
    let explicit = opt(args, "-c", "--config");
    let path = explicit.clone().unwrap_or_else(|| config::DEFAULT_PATH.into());
    match Config::load(&path, explicit.is_some()) {
        Ok(c) => c,
        Err(e) => die(&e),
    }
}

fn die(msg: &str) -> ! {
    eprintln!("loger: {}", msg);
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(|s| s.as_str()).unwrap_or("help");
    let rest = &args[args.len().min(1)..];
    match cmd {
        "daemon" => daemon(load_config(rest)),
        "show" => {
            let cfg = load_config(rest);
            let dir = opt(rest, "-d", "--dir").unwrap_or(cfg.log.dir);
            let f = show::Filter::parse(rest).unwrap_or_else(|e| die(&e));
            if let Err(e) = show::show(&PathBuf::from(dir), &f) {
                die(&e);
            }
        }
        "verify" => verify(rest),
        "receive" => {
            if let Err(e) = remote::receive(&load_config(rest)) {
                die(&e);
            }
        }
        "keygen" => println!("{}", remote::keygen()),
        "config" => print!("{}", config::SAMPLE),
        "version" | "--version" | "-V" => println!("loger {}", env!("CARGO_PKG_VERSION")),
        "help" | "--help" | "-h" => print!("{}", HELP),
        o => die(&format!("comando desconhecido: {} (veja `loger help`)", o)),
    }
}

fn verify(args: &[String]) {
    let cfg = load_config(args);
    let dir = PathBuf::from(opt(args, "-d", "--dir").unwrap_or(cfg.log.dir));
    let mut rep = store::verify(&dir).unwrap_or_else(|e| die(&format!("{} (rode como root?)", e)));
    println!("{} registros conferidos em {}", rep.records, dir.display());
    match rep.first_seq.filter(|s| *s > 0) {
        Some(s) if rep.rotated_files == 0 => rep.problems.insert(0, format!(
            "os registros 0 a {} não existem e não houve rotação: o log foi apagado ou truncado", s - 1
        )),
        Some(s) => println!("obs: o registro mais antigo é o seq {} (os anteriores podem ter saído pela rotação)", s),
        None => {}
    }
    if rep.problems.is_empty() {
        println!("OK: nenhum registro alterado, removido ou inserido.");
    } else {
        println!("PROBLEMAS ENCONTRADOS ({}):", rep.problems.len());
        for p in &rep.problems {
            println!("  - {}", p);
        }
        std::process::exit(1);
    }
}

/// Garante uma única instância por diretório de log (duas quebrariam a corrente de hashes).
fn lock_dir(dir: &std::path::Path) -> std::fs::File {
    use std::os::unix::io::AsRawFd;
    let _ = std::fs::create_dir_all(dir);
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join(".lock"))
        .unwrap_or_else(|e| die(&format!("{}: {} (rode como root?)", dir.display(), e)));
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        die("já existe um loger daemon rodando com este diretório de log");
    }
    f
}

fn daemon(cfg: Config) {
    if !util::is_root() {
        eprintln!("loger: aviso: rodando sem root — vários coletores vão funcionar parcialmente");
    }
    let dir = PathBuf::from(&cfg.log.dir);
    let _lock = lock_dir(&dir);
    let host = util::hostname();
    let mut st = store::Store::open(&dir, cfg.log.max_size_mb, cfg.log.keep, cfg.log.harden, &host)
        .unwrap_or_else(|e| die(&format!("{}: {}", dir.display(), e)));

    unsafe {
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
    }

    let cfg = Arc::new(cfg);
    let (tx, rx) = mpsc::sync_channel::<Ev>(8192);

    let remote_tx = if cfg.remote.enabled {
        let (rtx, rrx) = mpsc::sync_channel::<String>(4096);
        let (rc, etx) = (cfg.remote.clone(), tx.clone());
        std::thread::Builder::new().name("remote".into()).spawn(move || remote::sender(rc, rrx, etx)).ok();
        Some(rtx)
    } else {
        None
    };

    let uptime = util::read_text("/proc/uptime", 64)
        .and_then(|s| s.split('.').next()?.parse::<u64>().ok())
        .unwrap_or(0);
    let kernel = util::read_text("/proc/sys/kernel/osrelease", 128).unwrap_or_default().trim().to_string();
    let mut start = vec![Ev::new(
        "loger.start",
        INFO,
        format!("Loger {} iniciado (kernel {}, ligado há {}s)", env!("CARGO_PKG_VERSION"), kernel, uptime),
    )
    .data(serde_json::json!({ "pid": std::process::id(), "kernel": kernel, "uptime_secs": uptime, "remote": cfg.remote.enabled }))];
    if let Some(k) = st.last_kind.as_deref().filter(|k| *k != "loger.stop") {
        start.push(Ev::new(
            "loger.unclean_stop",
            WARN,
            format!(
                "a execução anterior terminou sem desligamento limpo (último evento: {} em {}) — kill -9, crash ou queda de energia",
                k,
                st.last_ts.clone().unwrap_or_default()
            ),
        ));
    }

    let ctx = collectors::Ctx { tx: tx.clone(), cfg: cfg.clone() };
    collectors::start_all(&ctx);

    let write = |st: &mut store::Store, ev: Ev| match st.append(ev) {
        Ok(line) => {
            if let Some(r) = &remote_tx {
                let _ = r.try_send(line);
            }
        }
        Err(e) => eprintln!("loger: falha ao gravar: {}", e),
    };
    for ev in start {
        write(&mut st, ev);
    }

    let mut last_tick = Instant::now();
    loop {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(ev) => write(&mut st, ev),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        if last_tick.elapsed() >= Duration::from_secs(1) {
            last_tick = Instant::now();
            if let Some(ev) = st.tick() {
                write(&mut st, ev);
            }
        }
        let sig = STOP.load(Ordering::SeqCst);
        if sig != 0 {
            while let Ok(ev) = rx.try_recv() {
                write(&mut st, ev);
            }
            let name = if sig == libc::SIGTERM { "SIGTERM" } else { "SIGINT" };
            write(&mut st, Ev::new("loger.stop", WARN, format!("Loger parado ({})", name)));
            st.log.sync();
            // Dá um instante para a thread remota mandar os últimos eventos.
            drop(remote_tx);
            std::thread::sleep(Duration::from_millis(500));
            return;
        }
    }
}
