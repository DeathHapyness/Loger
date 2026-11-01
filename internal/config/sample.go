package config

// Sample é a configuração de exemplo impressa por `loger config`.
const Sample = `# Configuração do Loger. Tudo é opcional: o que faltar usa o padrão mostrado aqui.

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

# Regras para ignorar comandos (e as conexões de rede deles). Numa regra, todos os campos
# preenchidos precisam casar; basta uma regra casar para ignorar.
#   exe, parent  binário do processo e do pai; * não passa de uma pasta para outra
#   user         usuário do evento (quem fez login)
#   argv         linha de comando inteira; * casa qualquer coisa, inclusive espaços
#
# [[exec.ignore]]
# exe = "/usr/lib/*/zabbix_agentd"
#
# [[exec.ignore]]
# user = "backup"
# exe = "/usr/bin/rsync"
#
# [[exec.ignore]]
# parent = "/usr/sbin/cron"
# argv = "*--healthcheck*"

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

# Envio remoto: cada evento é copiado na hora para outra máquina rodando "loger receive".
# Gere a chave com "loger keygen" e use a MESMA chave aqui e no receptor.
[remote]
enabled = false
address = "10.0.0.5:6514"
key = ""
queue_size = 20000         # eventos guardados em memória enquanto o receptor está fora
heartbeat_secs = 30        # sinal de vida; o receptor alerta se o host ficar mudo

# Usado só pelo "loger receive" (na máquina que recebe os logs).
[receiver]
listen = "0.0.0.0:6514"
key = ""
dir = "/var/log/loger-remote"
silent_after_secs = 120    # alerta se um host parar de mandar sinal de vida
`
