//! Funções pequenas usadas em todo o projeto: tempo, hex, base64, leitura de arquivos.

use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Formata epoch em ms como RFC3339 UTC: 2026-10-04T12:00:01.123Z
pub fn fmt_utc(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let (y, m, d) = civil_from_days(secs.div_euclid(86400));
    let rem = secs.rem_euclid(86400);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        y, m, d, rem / 3600, (rem % 3600) / 60, rem % 60, ms % 1000
    )
}

/// Inverso de `fmt_utc`.
pub fn parse_utc(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 20 {
        return None;
    }
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let days = days_from_civil(n(0..4)?, n(5..7)? as u32, n(8..10)? as u32);
    let secs = days * 86400 + n(11..13)? * 3600 + n(14..16)? * 60 + n(17..19)?;
    let ms = if b.get(19) == Some(&b'.') { n(20..23).unwrap_or(0) } else { 0 };
    Some((secs * 1000 + ms) as u64)
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = yoe as i64 + era * 400;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = (y - era * 400) as u64;
    let mp = (if m > 2 { m - 3 } else { m + 9 }) as u64;
    let doy = (153 * mp + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

extern "C" {
    fn tzset();
}

/// Formata no fuso horário local da máquina (lê /etc/localtime).
pub fn fmt_local(ms: u64) -> String {
    let t = (ms / 1000) as _;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe {
        tzset();
        libc::localtime_r(&t, &mut tm);
    }
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec
    )
}

/// Aceita "30s", "15m", "2h", "7d", "1w" (relativo a agora) ou
/// "2026-10-04", "2026-10-04 13:00", "2026-10-04T13:00:05" (hora local).
pub fn parse_when(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(unit) = s.chars().last().filter(|c| c.is_ascii_alphabetic()) {
        if let Ok(n) = s[..s.len() - 1].parse::<u64>() {
            let mult = match unit {
                's' => 1,
                'm' => 60,
                'h' => 3600,
                'd' => 86400,
                'w' => 7 * 86400,
                _ => return None,
            };
            return Some(now_ms().saturating_sub(n * mult * 1000));
        }
    }
    let s = s.replace('T', " ");
    let (date, time) = s.split_once(' ').unwrap_or((&s, "00:00:00"));
    let d: Vec<i32> = date.split('-').filter_map(|x| x.parse().ok()).collect();
    let t: Vec<i32> = time.split(':').filter_map(|x| x.parse().ok()).collect();
    if d.len() != 3 || t.is_empty() {
        return None;
    }
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    tm.tm_year = d[0] - 1900;
    tm.tm_mon = d[1] - 1;
    tm.tm_mday = d[2];
    tm.tm_hour = t[0];
    tm.tm_min = *t.get(1).unwrap_or(&0);
    tm.tm_sec = *t.get(2).unwrap_or(&0);
    tm.tm_isdst = -1;
    let secs = unsafe { libc::mktime(&mut tm) };
    if secs < 0 {
        return None;
    }
    Some(secs as u64 * 1000)
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex(&Sha256::digest(data))
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0;
    for c in s.bytes() {
        if c == b'=' {
            break;
        }
        let v = B64.iter().position(|&x| x == c)? as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

/// Base64 sem padding (formato usado pelo OpenSSH em "SHA256:...").
pub fn b64_encode_nopad(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk.iter().fold(0u32, |a, &b| (a << 8) | b as u32) << (8 * (3 - chunk.len()));
        for i in 0..=chunk.len() {
            out.push(B64[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

/// Fingerprint de chave pública SSH no mesmo formato do sshd ("SHA256:abc...").
pub fn ssh_fingerprint(b64_key: &str) -> Option<String> {
    use sha2::{Digest, Sha256};
    let raw = b64_decode(b64_key)?;
    Some(format!("SHA256:{}", b64_encode_nopad(&Sha256::digest(&raw))))
}

/// Lê um arquivo pequeno como texto (lossy), com limite de tamanho.
pub fn read_text(path: impl AsRef<Path>, limit: usize) -> Option<String> {
    let mut f = fs::File::open(path).ok()?;
    let mut buf = Vec::new();
    f.by_ref().take(limit as u64).read_to_end(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// Lê a última linha completa de um arquivo (sem carregar o arquivo inteiro).
pub fn last_line(path: impl AsRef<Path>) -> Option<String> {
    let mut f = fs::File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    if len == 0 {
        return None;
    }
    let start = len.saturating_sub(256 * 1024);
    f.seek(SeekFrom::Start(start)).ok()?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf);
    text.lines().rev().find(|l| !l.trim().is_empty()).map(|l| l.to_string())
}

pub fn hostname() -> String {
    read_text("/proc/sys/kernel/hostname", 256)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "desconhecido".into())
}

pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Junta argv num texto legível, com aspas onde precisa.
pub fn join_argv(argv: &[String]) -> String {
    argv.iter()
        .map(|a| {
            if a.is_empty() {
                "''".to_string()
            } else if a.chars().any(|c| c.is_whitespace() || "'\"$`\\|&;<>(){}*?".contains(c)) {
                format!("'{}'", a.replace('\'', "'\\''"))
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_roundtrip() {
        for ms in [0u64, 1_759_579_201_123, 951_782_400_000, 4_102_444_799_999] {
            assert_eq!(parse_utc(&fmt_utc(ms)), Some(ms));
        }
        assert_eq!(fmt_utc(1_759_579_201_123), "2025-10-04T12:00:01.123Z");
    }

    #[test]
    fn base64() {
        assert_eq!(b64_encode_nopad(b"hello"), "aGVsbG8");
        assert_eq!(b64_decode("aGVsbG8=").unwrap(), b"hello");
    }
}
