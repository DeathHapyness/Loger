//! Formato dos eventos.
//!
//! `Ev` é o que os coletores produzem. O escritor transforma em `Record`, numera (`seq`),
//! encadeia com o hash do registro anterior (`prev`) e calcula o próprio `hash`.

use crate::util;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const INFO: &str = "info";
pub const NOTICE: &str = "notice";
pub const WARN: &str = "warn";
pub const ALERT: &str = "alert";

pub fn level_rank(l: &str) -> u8 {
    match l {
        INFO => 0,
        NOTICE => 1,
        WARN => 2,
        ALERT => 3,
        _ => 0,
    }
}

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone)]
pub struct Ev {
    pub ts_ms: u64,
    pub kind: String,
    pub level: &'static str,
    pub user: String,
    pub msg: String,
    pub data: Value,
}

impl Ev {
    pub fn new(kind: &str, level: &'static str, msg: impl Into<String>) -> Ev {
        Ev {
            ts_ms: util::now_ms(),
            kind: kind.to_string(),
            level,
            user: String::new(),
            msg: msg.into(),
            data: Value::Null,
        }
    }

    pub fn user(mut self, u: impl Into<String>) -> Ev {
        self.user = u.into();
        self
    }

    pub fn data(mut self, d: Value) -> Ev {
        self.data = d;
        self
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Record {
    pub seq: u64,
    pub ts: String,
    pub host: String,
    pub kind: String,
    pub level: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub user: String,
    pub msg: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub data: Value,
    pub prev: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hash: String,
}

impl Record {
    pub fn from_ev(ev: Ev, seq: u64, host: &str, prev: &str) -> Record {
        let mut r = Record {
            seq,
            ts: util::fmt_utc(ev.ts_ms),
            host: host.to_string(),
            kind: ev.kind,
            level: ev.level.to_string(),
            user: ev.user,
            msg: ev.msg,
            data: ev.data,
            prev: prev.to_string(),
            hash: String::new(),
        };
        r.hash = r.compute_hash();
        r
    }

    /// sha256 do JSON do registro sem o campo `hash`. Como `prev` entra no cálculo,
    /// alterar ou remover qualquer registro quebra a corrente a partir dali.
    pub fn compute_hash(&self) -> String {
        let mut copy = self.clone();
        copy.hash.clear();
        util::sha256_hex(serde_json::to_string(&copy).unwrap_or_default().as_bytes())
    }

    pub fn ts_ms(&self) -> u64 {
        util::parse_utc(&self.ts).unwrap_or(0)
    }

    pub fn to_line(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_survives_roundtrip() {
        let ev = Ev::new("exec", INFO, "ls -la 'a b' ção")
            .user("joao")
            .data(serde_json::json!({"z": 1, "a": [1, 2], "s": "x\"\n\u{1}"}));
        let r = Record::from_ev(ev, 7, "srv", GENESIS);
        let back: Record = serde_json::from_str(&r.to_line()).unwrap();
        assert_eq!(back.compute_hash(), r.hash);
    }
}
