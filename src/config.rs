//! Configuração (TOML). Tudo tem valor padrão: sem arquivo, o Loger roda com os padrões.

use serde::Deserialize;
use std::path::Path;

pub const DEFAULT_PATH: &str = "/etc/loger/loger.toml";

#[derive(Deserialize, Clone, Debug)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub log: LogCfg,
    pub exec: ExecCfg,
    pub auth: AuthCfg,
    pub files: FilesCfg,
    pub net: NetCfg,
    pub system: SystemCfg,
    pub remote: RemoteCfg,
    pub receiver: ReceiverCfg,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(default, deny_unknown_fields)]
pub struct LogCfg {
    pub dir: String,
    pub max_size_mb: u64,
    pub keep: usize,
    pub harden: bool,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(default, deny_unknown_fields)]
pub struct ExecCfg {
    pub enabled: bool,
    pub only_sessions: bool,
    pub ignore_exe: Vec<String>,
    pub max_args_len: usize,
    pub poll_interval_ms: u64,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(default, deny_unknown_fields)]
pub struct AuthCfg {
    pub enabled: bool,
    pub files: Vec<String>,
    pub bruteforce_threshold: u32,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(default, deny_unknown_fields)]
pub struct FilesCfg {
    pub enabled: bool,
    pub watch: Vec<String>,
    pub watch_reads: Vec<String>,
    pub authorized_keys: bool,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(default, deny_unknown_fields)]
pub struct NetCfg {
    pub enabled: bool,
    pub interval_ms: u64,
    pub listen: bool,
    pub outbound: bool,
    pub only_sessions: bool,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(default, deny_unknown_fields)]
pub struct SystemCfg {
    pub enabled: bool,
    pub clock: bool,
    pub modules: bool,
    pub mounts: bool,
    pub ignore_mounts: Vec<String>,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(default, deny_unknown_fields)]
pub struct RemoteCfg {
    pub enabled: bool,
    pub address: String,
    pub key: String,
    pub queue_size: usize,
    pub heartbeat_secs: u64,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(default, deny_unknown_fields)]
pub struct ReceiverCfg {
    pub listen: String,
    pub key: String,
    pub dir: String,
    pub silent_after_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            log: LogCfg::default(),
            exec: ExecCfg::default(),
            auth: AuthCfg::default(),
            files: FilesCfg::default(),
            net: NetCfg::default(),
            system: SystemCfg::default(),
            remote: RemoteCfg::default(),
            receiver: ReceiverCfg::default(),
        }
    }
}

impl Default for LogCfg {
    fn default() -> Self {
        LogCfg { dir: "/var/log/loger".into(), max_size_mb: 50, keep: 20, harden: true }
    }
}

impl Default for ExecCfg {
    fn default() -> Self {
        ExecCfg {
            enabled: true,
            only_sessions: true,
            ignore_exe: vec![],
            max_args_len: 4096,
            poll_interval_ms: 500,
        }
    }
}

impl Default for AuthCfg {
    fn default() -> Self {
        AuthCfg {
            enabled: true,
            files: vec!["/var/log/auth.log".into(), "/var/log/secure".into()],
            bruteforce_threshold: 10,
        }
    }
}

impl Default for FilesCfg {
    fn default() -> Self {
        let watch = [
            "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
            "/etc/sudoers", "/etc/sudoers.d", "/etc/ssh", "/etc/pam.d",
            "/etc/crontab", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
            "/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron",
            "/etc/systemd/system", "/etc/ld.so.preload", "/etc/ld.so.conf.d",
            "/etc/hosts", "/etc/profile.d", "/etc/rc.local",
        ];
        FilesCfg {
            enabled: true,
            watch: watch.iter().map(|s| s.to_string()).collect(),
            watch_reads: vec![],
            authorized_keys: true,
        }
    }
}

impl Default for NetCfg {
    fn default() -> Self {
        NetCfg { enabled: true, interval_ms: 2000, listen: true, outbound: true, only_sessions: true }
    }
}

impl Default for SystemCfg {
    fn default() -> Self {
        let ignore = [
            "/proc", "/sys", "/dev", "/run/user/", "/run/docker", "/run/netns",
            "/run/snapd", "/var/lib/docker", "/var/lib/containers", "/snap/", "/run/credentials",
        ];
        SystemCfg {
            enabled: true,
            clock: true,
            modules: true,
            mounts: true,
            ignore_mounts: ignore.iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl Default for RemoteCfg {
    fn default() -> Self {
        RemoteCfg {
            enabled: false,
            address: String::new(),
            key: String::new(),
            queue_size: 20_000,
            heartbeat_secs: 30,
        }
    }
}

impl Default for ReceiverCfg {
    fn default() -> Self {
        ReceiverCfg {
            listen: "0.0.0.0:6514".into(),
            key: String::new(),
            dir: "/var/log/loger-remote".into(),
            silent_after_secs: 120,
        }
    }
}

impl Config {
    /// Carrega o arquivo. Se `explicit` for falso e o arquivo não existir, usa os padrões.
    pub fn load(path: &str, explicit: bool) -> Result<Config, String> {
        if !Path::new(path).exists() {
            if explicit {
                return Err(format!("arquivo de configuração não encontrado: {}", path));
            }
            return Ok(Config::default());
        }
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {}", path, e))?;
        toml::from_str(&text).map_err(|e| format!("{}: {}", path, e))
    }
}

/// Configuração de exemplo, com comentários, impressa por `loger config`.
pub const SAMPLE: &str = r#"# Configuração do Loger. Tudo é opcional: o que faltar usa o padrão mostrado aqui.

[log]
dir = "/var/log/loger"     # onde os logs ficam
max_size_mb = 50           # tamanho de cada arquivo antes de rotacionar
keep = 20                  # quantos arquivos antigos manter
harden = true              # marca os logs como append-only (chattr +a) quando o FS suporta

[exec]
enabled = true
only_sessions = true       # só comandos de quem fez login (ssh/console); false = todos os processos
ignore_exe = []            # binários a ignorar, ex: ["/usr/bin/sleep"]
max_args_len = 4096
poll_interval_ms = 500     # usado só se o kernel não aceitar o proc connector

[auth]
enabled = true
files = ["/var/log/auth.log", "/var/log/secure"]   # sem nenhum deles: journalctl, depois /var/log/btmp
bruteforce_threshold = 10  # falhas do mesmo IP em 60s para gerar alerta de força bruta

[files]
enabled = true
watch = [
  "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
  "/etc/sudoers", "/etc/sudoers.d", "/etc/ssh", "/etc/pam.d",
  "/etc/crontab", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
  "/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron",
  "/etc/systemd/system", "/etc/ld.so.preload", "/etc/ld.so.conf.d",
  "/etc/hosts", "/etc/profile.d", "/etc/rc.local",
]
watch_reads = []           # arquivos onde até a LEITURA é registrada, ex: ["/etc/shadow"]
authorized_keys = true     # vigia ~/.ssh/authorized_keys de todos os usuários

[net]
enabled = true
interval_ms = 2000
listen = true              # portas novas abertas
outbound = true            # conexões de saída
only_sessions = true       # conexões de saída só de processos de usuários logados

[system]
enabled = true
clock = true               # mudança de hora do sistema
modules = true             # módulos do kernel carregados/removidos
mounts = true              # discos/pendrives montados
ignore_mounts = ["/proc", "/sys", "/dev", "/run/user/", "/run/docker", "/run/netns",
                 "/run/snapd", "/var/lib/docker", "/var/lib/containers", "/snap/", "/run/credentials"]

# Envio remoto: cada evento é copiado na hora para outra máquina rodando `loger receive`.
# Gere a chave com `loger keygen` e use a MESMA chave aqui e no receptor.
[remote]
enabled = false
address = "10.0.0.5:6514"
key = ""
queue_size = 20000         # eventos guardados em memória enquanto o receptor está fora
heartbeat_secs = 30        # sinal de vida; o receptor alerta se o host ficar mudo

# Usado só pelo `loger receive` (na máquina que recebe os logs).
[receiver]
listen = "0.0.0.0:6514"
key = ""
dir = "/var/log/loger-remote"
silent_after_secs = 120    # alerta se um host parar de mandar sinal de vida
"#;

#[cfg(test)]
mod tests {
    #[test]
    fn sample_parses() {
        let c: super::Config = toml::from_str(super::SAMPLE).unwrap();
        assert_eq!(c.log.keep, 20);
    }
}
