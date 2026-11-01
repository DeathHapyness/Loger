# Loger

Auditoria leve para servidores Linux. É um binário estático de ~1,2 MB, usa ~3 MB de RAM e não depende de nada instalado no servidor: não precisa de auditd, eBPF, Python nem de bibliotecas do sistema.

## O que registra

| Categoria | Eventos (`kind`) |
|---|---|
| Logins | `session.start` / `session.end` (usuário, IP de origem, tty, duração, nº de comandos), `ssh.auth_ok` (método e fingerprint da chave), `ssh.auth_fail`, `ssh.bruteforce` |
| Comandos | `exec` com argumentos, diretório, pid/ppid e tty. Cada comando fica ligado à sessão de login (`ses`), **inclusive depois de `sudo`/`su`** |
| Privilégios | `priv.cmd` (sudo/su), `priv.sudo_denied`, `priv.su_fail`, `priv.escalation` (virou root sem binário setuid = exploit) |
| Comandos suspeitos | `exec.suspicious` (binário rodando de /tmp, /dev/shm), binário apagado do disco, `exec.net_tool` (nc, socat…), `exec.antiforensics` |
| Arquivos sensíveis | `file.created` / `modified` / `deleted` / `perm` em /etc/passwd, shadow, sudoers, ssh, pam, cron, systemd, ld.so.preload… |
| Contas | `account.user_added` / `removed` / `changed` (alerta se virar uid 0), `account.group_member_added` (alerta para sudo/wheel/docker…) |
| Chaves SSH | `ssh.key_added` / `ssh.key_removed` em qualquer `authorized_keys`, com o fingerprint da chave |
| Rede | `net.listen` (porta nova), `net.connect` (conexão de saída de usuário logado), `net.shell_socket` (shell com socket = reverse shell) |
| Sistema | `system.clock_changed`, `kernel.module_loaded`, `mount.added`, `firewall.cmd`, `system.power_cmd` |
| O próprio Loger | `loger.stop`, `loger.unclean_stop` (foi morto com kill -9), `loger.log_tampered` (log apagado/truncado), `loger.events_lost` |

Níveis: `info`, `notice`, `warn`, `alert`.

## Compilar

```sh
rustup target add x86_64-unknown-linux-musl          # uma vez
cargo build --release --target x86_64-unknown-linux-musl
# binário: target/x86_64-unknown-linux-musl/release/loger
```

Para ARM (Raspberry Pi, servidores Graviton), use o target `aarch64-unknown-linux-musl`.

## Instalar

```sh
sudo cp target/x86_64-unknown-linux-musl/release/loger /usr/local/bin/
sudo mkdir -p /etc/loger && loger config | sudo tee /etc/loger/loger.toml   # opcional
sudo cp dist/loger.service /etc/systemd/system/
sudo systemctl enable --now loger
```

Sem systemd (Alpine/OpenRC, por exemplo), basta deixar `loger daemon` rodando como root pelo init da distro.

## Consultar

```sh
sudo loger show -n 50                     # últimos 50 eventos
sudo loger show -f                        # em tempo real
sudo loger show -k session                # quem logou, de onde e por quanto tempo
sudo loger show --ses 12                  # tudo o que aconteceu numa sessão
sudo loger show -u joao -s 2h             # o que o joao fez nas últimas 2h
sudo loger show -l alert -s 7d            # só alertas da última semana
sudo loger show -k ssh.auth_fail -g 1.2.3.4
sudo loger show --json | jq ...           # para scripts
sudo loger verify                         # confere se alguém mexeu nos logs
```

## Envio remoto

Se alguém invadir o servidor e virar root, pode apagar os logs locais. Com o envio remoto, cada evento é copiado na hora para outra máquina, e o que já saiu o invasor não consegue mais apagar.

Na máquina que vai **receber**:

```sh
loger keygen                                    # gera a chave; guarde
# /etc/loger/loger.toml
[receiver]
listen = "0.0.0.0:6514"
key = "<chave>"
dir = "/var/log/loger-remote"

sudo cp dist/loger-receiver.service /etc/systemd/system/ && sudo systemctl enable --now loger-receiver
```

Em cada servidor **auditado**:

```toml
[remote]
enabled = true
address = "ip-do-receptor:6514"
key = "<mesma chave>"
```

- O tráfego é cifrado e autenticado com XChaCha20-Poly1305. Quem não tem a chave não consegue ler nem forjar eventos.
- Se o receptor cair, os eventos ficam numa fila em memória e são reenviados quando ele voltar.
- O receptor guarda cada host em `/var/log/loger-remote/<host>/` e avisa no próprio log (`/var/log/loger-remote/_receiver`) quando:
  - um host para de mandar sinal de vida (`remote.host_silent`);
  - faltam registros na sequência (`remote.chain_gap`);
  - a sequência volta para trás, sinal de que o log local foi apagado (`remote.chain_reset`);
  - alguém tenta conectar com a chave errada.
- Consulta: `loger show -d /var/log/loger-remote/<host>` e `loger verify -d ...`.

## Proteção dos logs

- **Corrente de hashes:** cada registro guarda o hash do anterior. Alterar, remover ou inserir uma linha é detectado pelo `loger verify`.
- **Append-only:** os arquivos recebem `chattr +a` (em ext4, xfs e btrfs). Nem o root consegue editar ou apagar sem antes remover o atributo.
- **Monitoramento do próprio log:** se o arquivo for apagado, trocado ou truncado com o daemon rodando, ele registra `loger.log_tampered` e continua num arquivo novo.
- **Paradas:** a parada do daemon é registrada. Se ele for morto com `kill -9`, o próximo início registra `loger.unclean_stop`.

## Limitações (sem depender de recursos especiais do kernel)

- **Comandos:** vêm do *proc connector* do kernel, que existe em todo Linux desde 2.6.15. Para um processo que termina em microssegundos, os argumentos podem não dar tempo de serem lidos: o evento é registrado, mas sem os argumentos. Sem o proc connector (container restrito), o Loger faz varredura do `/proc` a cada 500 ms, e aí processos muito curtos podem escapar.
- **Arquivos:** o inotify mostra *o que* mudou, mas não *quem* mudou. Para descobrir quem, cruze com os comandos no mesmo horário (`loger show -s ...`).
- **Rede:** a varredura é feita a cada 2 s, então conexões que abrem e fecham mais rápido que isso podem não aparecer.
- **Root no servidor:** quem é root pode desligar qualquer ferramenta de auditoria. O que garante a evidência é o envio remoto, que avisa quando o host fica mudo.
