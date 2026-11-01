//! Envio remoto: cada registro é copiado na hora para outra máquina (`loger receive`).
//!
//! Protocolo: TCP, quadros [u32 big-endian tamanho][nonce 24 bytes][dados cifrados].
//! Cifra: XChaCha20-Poly1305 com chave compartilhada (gerada por `loger keygen`), que
//! garante sigilo e que ninguém sem a chave consegue forjar ou alterar eventos.

use crate::config::{Config, ReceiverCfg, RemoteCfg};
use crate::event::{Ev, Record, ALERT, INFO, NOTICE, WARN};
use crate::store::{last_record, LogFile, Store};
use crate::util::{self, hostname, now_ms, unhex};
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde_json::json;
use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_FRAME: usize = 1 << 20;

pub fn parse_key(hex: &str) -> Result<XChaCha20Poly1305, String> {
    let k = unhex(hex).filter(|k| k.len() == 32).ok_or("chave inválida: use `loger keygen` (64 caracteres hex)")?;
    XChaCha20Poly1305::new_from_slice(&k).map_err(|e| e.to_string())
}

pub fn keygen() -> String {
    util::hex(&XChaCha20Poly1305::generate_key(&mut OsRng))
}

fn write_frame(s: &mut TcpStream, c: &XChaCha20Poly1305, plain: &[u8]) -> io::Result<()> {
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = c.encrypt(&nonce, plain).map_err(|_| io::Error::other("falha ao cifrar"))?;
    let mut buf = Vec::with_capacity(4 + 24 + ct.len());
    buf.extend_from_slice(&((24 + ct.len()) as u32).to_be_bytes());
    buf.extend_from_slice(&nonce);
    buf.extend_from_slice(&ct);
    s.write_all(&buf)
}

fn read_frame(s: &mut TcpStream, c: &XChaCha20Poly1305) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    s.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if !(24..=MAX_FRAME).contains(&len) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "quadro com tamanho inválido"));
    }
    let mut buf = vec![0u8; len];
    s.read_exact(&mut buf)?;
    c.decrypt(XNonce::from_slice(&buf[..24]), &buf[24..])
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "chave errada ou dados adulterados"))
}

// ---------------- lado que envia (daemon) ----------------

/// Thread de envio. Recebe linhas já gravadas localmente; se o receptor estiver fora, guarda
/// em memória até `queue_size` e reenvia quando a conexão voltar.
pub fn sender(cfg: RemoteCfg, rx: Receiver<String>, events: SyncSender<Ev>) {
    let cipher = match parse_key(&cfg.key) {
        Ok(c) => c,
        Err(e) => {
            let _ = events.send(Ev::new("loger.remote", ALERT, format!("envio remoto desativado: {}", e)));
            return;
        }
    };
    let host = hostname();
    let mut queue: VecDeque<String> = VecDeque::new();
    let mut conn: Option<TcpStream> = None;
    let mut dropped: u64 = 0;
    let mut next_try = Instant::now();
    let mut backoff = Duration::from_secs(1);
    let mut last_hb = Instant::now() - Duration::from_secs(3600);
    let mut was_down = false;

    loop {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(line) => {
                queue.push_back(line);
                queue.extend(rx.try_iter());
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                if let Some(s) = conn.as_mut() {
                    for l in queue.drain(..) {
                        let _ = write_frame(s, &cipher, l.as_bytes());
                    }
                }
                return;
            }
        }
        while queue.len() > cfg.queue_size.max(100) {
            queue.pop_front();
            dropped += 1;
        }

        if conn.is_none() && Instant::now() >= next_try {
            match connect(&cfg.address) {
                Ok(s) => {
                    conn = Some(s);
                    backoff = Duration::from_secs(1);
                    if was_down {
                        let _ = events.try_send(Ev::new("loger.remote", NOTICE, format!("reconectado ao receptor {} ({} eventos na fila)", cfg.address, queue.len())));
                    }
                    was_down = false;
                }
                Err(e) => {
                    if !was_down {
                        let _ = events.try_send(Ev::new("loger.remote", WARN, format!("receptor {} inacessível: {} — guardando eventos em memória", cfg.address, e)));
                    }
                    was_down = true;
                    next_try = Instant::now() + backoff;
                    backoff = (backoff * 2).min(Duration::from_secs(60));
                }
            }
        }
        if let Some(s) = conn.as_mut() {
            let mut failed = false;
            if last_hb.elapsed() >= Duration::from_secs(cfg.heartbeat_secs.max(5)) {
                let hb = json!({ "heartbeat": true, "host": host, "ts": util::fmt_utc(now_ms()) }).to_string();
                failed = write_frame(s, &cipher, hb.as_bytes()).is_err();
                last_hb = Instant::now();
            }
            while !failed {
                let Some(line) = queue.front() else { break };
                if write_frame(s, &cipher, line.as_bytes()).is_err() {
                    failed = true;
                } else {
                    queue.pop_front();
                }
            }
            if failed {
                conn = None;
                was_down = true;
                next_try = Instant::now() + backoff;
                let _ = events.try_send(Ev::new("loger.remote", WARN, format!("conexão com receptor {} caiu", cfg.address)));
            }
        }
        if dropped > 0 {
            let _ = events.try_send(Ev::new("loger.remote_dropped", ALERT, format!("{} eventos descartados da fila de envio remoto (receptor fora por muito tempo)", dropped)));
            dropped = 0;
        }
    }
}

fn connect(addr: &str) -> io::Result<TcpStream> {
    let sa = addr.to_socket_addrs()?.next().ok_or_else(|| io::Error::other("endereço inválido"))?;
    let s = TcpStream::connect_timeout(&sa, Duration::from_secs(5))?;
    s.set_write_timeout(Some(Duration::from_secs(10)))?;
    s.set_nodelay(true)?;
    Ok(s)
}

// ---------------- lado que recebe ----------------

struct HostState {
    file: LogFile,
    last_seq: Option<u64>,
    last_hash: String,
    last_seen: Instant,
    silent: bool,
}

struct Shared {
    hosts: HashMap<String, HostState>,
    own: Store,
    dir: PathBuf,
    max_mb: u64,
    keep: usize,
}

impl Shared {
    fn event(&mut self, ev: Ev) {
        eprintln!("[{}] {} {}", ev.level, ev.kind, ev.msg);
        let _ = self.own.append(ev);
    }
}

fn safe_host(h: &str) -> String {
    let s: String = h.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' { c } else { '_' }).collect();
    let s = s.trim_start_matches('.').to_string();
    if s.is_empty() { "_".into() } else { s }
}

pub fn receive(cfg: &Config) -> Result<(), String> {
    let rc: ReceiverCfg = cfg.receiver.clone();
    let cipher = Arc::new(parse_key(&rc.key)?);
    let dir = PathBuf::from(&rc.dir);
    let own = Store::open(&dir.join("_receiver"), cfg.log.max_size_mb, cfg.log.keep, cfg.log.harden, &hostname())
        .map_err(|e| format!("{}: {}", dir.display(), e))?;
    let listener = TcpListener::bind(&rc.listen).map_err(|e| format!("{}: {}", rc.listen, e))?;
    let shared = Arc::new(Mutex::new(Shared { hosts: HashMap::new(), own, dir, max_mb: cfg.log.max_size_mb, keep: cfg.log.keep }));
    shared.lock().unwrap().event(Ev::new("receiver.start", INFO, format!("receptor ouvindo em {}", rc.listen)));

    let (sh, silent_after) = (shared.clone(), Duration::from_secs(rc.silent_after_secs.max(10)));
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(5));
        let mut g = sh.lock().unwrap();
        let mut evs = vec![];
        for (h, st) in g.hosts.iter_mut() {
            st.file.sync();
            if !st.silent && st.last_seen.elapsed() > silent_after {
                st.silent = true;
                evs.push(Ev::new("remote.host_silent", ALERT, format!("host {} parou de enviar sinal de vida há {}s (desligado, rede ou Loger morto?)", h, st.last_seen.elapsed().as_secs()))
                    .data(json!({ "host": h })));
            }
        }
        for e in evs {
            g.event(e);
        }
    });

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let (sh, c) = (shared.clone(), cipher.clone());
        std::thread::spawn(move || handle_conn(stream, &c, &sh));
    }
    Ok(())
}

fn handle_conn(mut s: TcpStream, c: &XChaCha20Poly1305, sh: &Mutex<Shared>) {
    let peer = s.peer_addr().map(|a| a.to_string()).unwrap_or_default();
    let _ = s.set_read_timeout(Some(Duration::from_secs(300)));
    let mut bound_host: Option<String> = None;
    loop {
        let plain = match read_frame(&mut s, c) {
            Ok(p) => p,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied || e.kind() == io::ErrorKind::InvalidData => {
                sh.lock().unwrap().event(Ev::new("remote.auth_failed", ALERT, format!("conexão de {} rejeitada: {}", peer, e)).data(json!({ "peer": peer })));
                return;
            }
            Err(_) => {
                if let Some(h) = &bound_host {
                    sh.lock().unwrap().event(Ev::new("remote.disconnected", NOTICE, format!("host {} ({}) desconectou", h, peer)).data(json!({ "host": h })));
                }
                return;
            }
        };
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(&plain) else { continue };
        let host = safe_host(v["host"].as_str().unwrap_or(""));
        if let Some(b) = &bound_host {
            if *b != host {
                sh.lock().unwrap().event(Ev::new("remote.host_mismatch", ALERT, format!("conexão de {} mandou eventos como {} e depois como {}", peer, b, host)));
                return;
            }
        }
        let mut g = sh.lock().unwrap();
        if !g.hosts.contains_key(&host) {
            let hdir = g.dir.join(&host);
            let Ok(file) = LogFile::open(&hdir, g.max_mb, g.keep, true) else { return };
            let last = last_record(&hdir);
            g.hosts.insert(host.clone(), HostState {
                file,
                last_seq: last.as_ref().map(|r| r.seq),
                last_hash: last.map(|r| r.hash).unwrap_or_default(),
                last_seen: Instant::now(),
                silent: false,
            });
        }
        if bound_host.is_none() {
            bound_host = Some(host.clone());
            g.event(Ev::new("remote.connected", INFO, format!("host {} conectado de {}", host, peer)).data(json!({ "host": host, "peer": peer })));
        }
        let st = g.hosts.get_mut(&host).unwrap();
        st.last_seen = Instant::now();
        let back = std::mem::replace(&mut st.silent, false);
        let mut evs = vec![];
        if back {
            evs.push(Ev::new("remote.host_back", NOTICE, format!("host {} voltou a enviar", host)));
        }
        if v.get("heartbeat").is_none() {
            let Ok(rec) = serde_json::from_value::<Record>(v) else { continue };
            if rec.compute_hash() != rec.hash {
                evs.push(Ev::new("remote.bad_record", ALERT, format!("{}: registro seq {} com hash inválido", host, rec.seq)));
            } else if let Some(ls) = st.last_seq {
                if rec.seq <= ls {
                    evs.push(Ev::new("remote.chain_reset", ALERT, format!("{}: sequência voltou de {} para {} (log local apagado/reiniciado?)", host, ls, rec.seq)));
                } else if rec.prev != st.last_hash {
                    evs.push(Ev::new("remote.chain_gap", WARN, format!("{}: faltam registros entre seq {} e {} (eventos perdidos durante queda do envio)", host, ls, rec.seq)));
                }
            }
            st.last_seq = Some(rec.seq);
            st.last_hash = rec.hash.clone();
            // Grava a linha original, assim `loger verify` funciona no diretório do host.
            if let Err(e) = st.file.append(&String::from_utf8_lossy(&plain)) {
                evs.push(Ev::new("remote.write_error", ALERT, format!("{}: falha ao gravar: {}", host, e)));
            }
        }
        for e in evs {
            g.event(e.data(json!({ "host": host })));
        }
    }
}
