# Loger

Auditoria leve para servidores Linux. É um binário estático, escrito em Go, que não depende de nada instalado no servidor: não precisa de auditd, eBPF, Python nem de bibliotecas do sistema. O binário tem cerca de 3 MB e o daemon usa uns 9 MB de RAM.

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
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o loger .
```

Para ARM (Raspberry Pi, servidores Graviton), acrescente `GOARCH=arm64` antes do comando.

## Instalar

```sh
sudo cp loger /usr/local/bin/
sudo mkdir -p /etc/loger && loger config | sudo tee /etc/loger/loger.toml   # opcional
sudo cp dist/loger.service /etc/systemd/system/
sudo systemctl enable --now loger
```

Sem systemd (Alpine/OpenRC, por exemplo), basta deixar `loger daemon` rodando como root pelo init da distro.

Depois de editar a configuração, `sudo systemctl reload loger` (ou `kill -HUP`) aplica as mudanças sem parar a coleta. Mudanças em `[log]`, `[remote]` ou em quais coletores estão ligados só valem depois de reiniciar, e o próprio Loger avisa isso no log.

## Container

Para rodar em Docker (por exemplo, dentro de um instalador self-hosted):

```sh
docker compose build
sudo mkdir -p /etc/loger && docker run --rm ghcr.io/deathhapyness/loger config | sudo tee /etc/loger/loger.toml   # opcional
docker compose up -d
docker exec loger /loger show -n 50
docker exec loger /loger report
```

O container monta a raiz do host em `/host`, só leitura, e com `LOGER_ROOT=/host` o Loger faz `chroot` nela ao iniciar. Assim ele enxerga o `/etc`, o `/home`, o journal e os processos do host como se estivesse instalado direto nele. A configuração continua em `/etc/loger/loger.toml` e os logs em `/var/log/loger`, ambos no host. O único diretório gravável é `/var/log/loger`.

Ele precisa de `pid: host`, `network_mode: host`, das capabilities listadas no `docker-compose.yml` e de `apparmor:unconfined`, porque o perfil padrão do Docker impede ler `/proc` de processos fora do container. Isso dá ao container acesso de leitura a tudo no host, o mesmo que o Loger instalado direto teria.

O receptor do envio remoto é opcional: `docker compose --profile receiver up -d`.

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
sudo loger report                         # resumo das últimas 24h
sudo loger report -s 7d -n 20             # resumo da semana, top 20 em cada lista
sudo loger report --json                  # o mesmo resumo em JSON
```

O `report` junta num resumo os logins e de onde vieram, as falhas de login por IP e por usuário tentado, a força bruta, os privilégios negados, as portas novas, as conexões de saída, os arquivos e contas alterados, os eventos do sistema, a integridade do próprio Loger e os comandos mais usados.

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
