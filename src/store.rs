//! Gravação dos logs em disco: arquivo de linhas JSON, só acréscimo, com rotação,
//! corrente de hashes e detecção de adulteração do próprio arquivo.

use crate::event::{Ev, Record, ALERT, GENESIS};
use crate::util;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const BASE: &str = "loger.log";

/// Arquivo com rotação. Usado tanto pelo daemon quanto pelo receptor remoto.
pub struct LogFile {
    dir: PathBuf,
    file: File,
    ino: u64,
    size: u64,
    max: u64,
    keep: usize,
    harden: bool,
}

impl LogFile {
    pub fn open(dir: &Path, max_size_mb: u64, keep: usize, harden: bool) -> io::Result<LogFile> {
        fs::create_dir_all(dir)?;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
        let (file, ino, size) = Self::open_current(dir, harden)?;
        Ok(LogFile { dir: dir.to_path_buf(), file, ino, size, max: max_size_mb.max(1) * 1024 * 1024, keep: keep.max(1), harden })
    }

    fn open_current(dir: &Path, harden: bool) -> io::Result<(File, u64, u64)> {
        let path = dir.join(BASE);
        let file = OpenOptions::new().create(true).append(true).mode(0o600).open(&path)?;
        if harden {
            set_append_only(&path, true);
        }
        let md = file.metadata()?;
        Ok((file, md.ino(), md.len()))
    }

    pub fn append(&mut self, line: &str) -> io::Result<()> {
        if self.size + line.len() as u64 + 1 > self.max && self.size > 0 {
            self.rotate()?;
        }
        let mut buf = Vec::with_capacity(line.len() + 1);
        buf.extend_from_slice(line.as_bytes());
        buf.push(b'\n');
        self.file.write_all(&buf)?;
        self.size += buf.len() as u64;
        Ok(())
    }

    fn rotate(&mut self) -> io::Result<()> {
        let name = |i: usize| self.dir.join(if i == 0 { BASE.to_string() } else { format!("{}.{}", BASE, i) });
        let oldest = name(self.keep);
        if oldest.exists() {
            set_append_only(&oldest, false);
            fs::remove_file(&oldest)?;
        }
        for i in (0..self.keep).rev() {
            let from = name(i);
            if from.exists() {
                set_append_only(&from, false);
                fs::rename(&from, name(i + 1))?;
                if self.harden {
                    set_append_only(&name(i + 1), true);
                }
            }
        }
        let (file, ino, size) = Self::open_current(&self.dir, self.harden)?;
        self.file = file;
        self.ino = ino;
        self.size = size;
        Ok(())
    }

    pub fn sync(&self) {
        let _ = self.file.sync_data();
    }

    /// Verifica se alguém apagou, trocou ou truncou o arquivo atual.
    /// Se sim, reabre um arquivo novo e devolve a descrição do problema.
    pub fn check_tamper(&mut self) -> Option<String> {
        let path = self.dir.join(BASE);
        let problem = match fs::metadata(&path) {
            Err(_) => Some(format!("{} foi apagado", path.display())),
            Ok(md) if md.ino() != self.ino => Some(format!("{} foi substituído por outro arquivo", path.display())),
            Ok(md) if md.len() < self.size => Some(format!(
                "{} foi truncado ({} -> {} bytes)", path.display(), self.size, md.len()
            )),
            Ok(_) => None,
        };
        if problem.is_some() {
            if let Ok((file, ino, size)) = Self::open_current(&self.dir, self.harden) {
                self.file = file;
                self.ino = ino;
                self.size = size;
            }
        }
        problem
    }
}

/// LogFile + corrente de hashes.
pub struct Store {
    pub log: LogFile,
    host: String,
    seq: u64,
    last_hash: String,
    pub last_kind: Option<String>,
    pub last_ts: Option<String>,
}

impl Store {
    pub fn open(dir: &Path, max_size_mb: u64, keep: usize, harden: bool, host: &str) -> io::Result<Store> {
        let log = LogFile::open(dir, max_size_mb, keep, harden)?;
        let mut s = Store { log, host: host.to_string(), seq: 0, last_hash: GENESIS.into(), last_kind: None, last_ts: None };
        if let Some(r) = last_record(dir) {
            s.seq = r.seq + 1;
            s.last_hash = r.hash;
            s.last_kind = Some(r.kind);
            s.last_ts = Some(r.ts);
        }
        Ok(s)
    }

    pub fn append(&mut self, ev: Ev) -> io::Result<String> {
        let rec = Record::from_ev(ev, self.seq, &self.host, &self.last_hash);
        let line = rec.to_line();
        self.log.append(&line)?;
        self.seq += 1;
        self.last_hash = rec.hash;
        Ok(line)
    }

    /// Chamado a cada segundo: fsync e verificação de adulteração.
    pub fn tick(&mut self) -> Option<Ev> {
        self.log.sync();
        self.log.check_tamper().map(|p| {
            Ev::new("loger.log_tampered", ALERT, format!("arquivo de log adulterado: {}", p))
        })
    }
}

/// Último registro gravado (olha o arquivo atual e, se vazio, o .1).
pub fn last_record(dir: &Path) -> Option<Record> {
    for name in [BASE.to_string(), format!("{}.1", BASE)] {
        if let Some(line) = util::last_line(dir.join(&name)) {
            if let Ok(r) = serde_json::from_str::<Record>(&line) {
                return Some(r);
            }
        }
    }
    None
}

/// Arquivos de log do diretório, do mais antigo para o mais novo.
pub fn log_files(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<(usize, PathBuf)> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let n = if name == BASE {
                0
            } else {
                name.strip_prefix(&format!("{}.", BASE))?.parse().ok()?
            };
            Some((n, e.path()))
        })
        .collect();
    v.sort_by(|a, b| b.0.cmp(&a.0));
    v.into_iter().map(|(_, p)| p).collect()
}

/// Lê todas as linhas (em ordem cronológica) chamando `f(arquivo, nº da linha, linha)`.
pub fn for_each_line(dir: &Path, mut f: impl FnMut(&Path, usize, &str)) -> io::Result<()> {
    let files = log_files(dir);
    if files.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("nenhum log em {}", dir.display())));
    }
    for path in files {
        let reader = BufReader::new(File::open(&path)?);
        for (i, line) in reader.split(b'\n').enumerate() {
            let line = line?;
            if !line.is_empty() {
                f(&path, i + 1, &String::from_utf8_lossy(&line));
            }
        }
    }
    Ok(())
}

/// chattr +a / -a via ioctl. Silencioso se o sistema de arquivos não suportar.
pub fn set_append_only(path: &Path, on: bool) {
    use std::os::unix::io::AsRawFd;
    const FS_APPEND_FL: libc::c_int = 0x20;
    let sz = std::mem::size_of::<libc::c_long>() as libc::c_ulong;
    let getflags = (2 << 30) | (sz << 16) | (0x66 << 8) | 1; // _IOR('f', 1, long)
    let setflags = (1 << 30) | (sz << 16) | (0x66 << 8) | 2; // _IOW('f', 2, long)
    let Ok(f) = File::open(path) else { return };
    let mut flags: libc::c_int = 0;
    unsafe {
        if libc::ioctl(f.as_raw_fd(), getflags as _, &mut flags) != 0 {
            return;
        }
        let new = if on { flags | FS_APPEND_FL } else { flags & !FS_APPEND_FL };
        if new != flags {
            libc::ioctl(f.as_raw_fd(), setflags as _, &new);
        }
    }
}

pub struct VerifyReport {
    pub records: u64,
    pub problems: Vec<String>,
    pub first_seq: Option<u64>,
    pub rotated_files: usize,
}

/// Confere hash de cada registro, o encadeamento e a sequência.
pub fn verify(dir: &Path) -> io::Result<VerifyReport> {
    let mut rep = VerifyReport { records: 0, problems: vec![], first_seq: None, rotated_files: log_files(dir).len().saturating_sub(1) };
    let mut prev: Option<(u64, String)> = None;
    for_each_line(dir, |path, n, line| {
        let loc = format!("{}:{}", path.display(), n);
        let r: Record = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => {
                rep.problems.push(format!("{}: linha ilegível ({})", loc, e));
                return;
            }
        };
        rep.records += 1;
        if rep.first_seq.is_none() {
            rep.first_seq = Some(r.seq);
        }
        if r.kind == "loger.log_tampered" || r.kind == "loger.unclean_stop" {
            rep.problems.push(format!("{}: o próprio Loger registrou: {}", loc, r.msg));
        }
        if r.compute_hash() != r.hash {
            rep.problems.push(format!("{}: seq {} foi ALTERADO (hash não confere)", loc, r.seq));
        }
        if let Some((pseq, phash)) = &prev {
            if r.prev != *phash {
                rep.problems.push(format!(
                    "{}: corrente quebrada entre seq {} e seq {} (registros removidos ou inseridos)",
                    loc, pseq, r.seq
                ));
            } else if r.seq != pseq + 1 {
                rep.problems.push(format!("{}: sequência pulou de {} para {}", loc, pseq, r.seq));
            }
        }
        prev = Some((r.seq, r.hash));
    })?;
    Ok(rep)
}
