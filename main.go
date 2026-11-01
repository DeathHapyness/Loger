package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/DeathHapyness/loger/internal/config"
	"github.com/DeathHapyness/loger/internal/daemon"
	"github.com/DeathHapyness/loger/internal/remote"
	"github.com/DeathHapyness/loger/internal/report"
	"github.com/DeathHapyness/loger/internal/show"
	"github.com/DeathHapyness/loger/internal/store"
	"golang.org/x/sys/unix"
)

var version = "0.2.0"

const help = `loger — auditoria leve para servidores Linux

USO:
  loger daemon   [-c CONFIG]          coleta eventos (rodar como root, normalmente via systemd)
  loger show     [-d DIR] [filtros]   mostra os eventos
  loger report   [-d DIR] [-s QUANDO] resumo do período (logins, falhas, alertas, portas)
  loger verify   [-d DIR]             confere se os logs foram alterados ou apagados
  loger receive  [-c CONFIG]          recebe logs de outros servidores (envio remoto)
  loger keygen                        gera a chave para o envio remoto
  loger config                        imprime uma configuração de exemplo comentada
  loger version

FILTROS DO show:
  -k, --kind TIPO     ex: ssh, session, exec, priv, file, account, net, system (vírgula p/ vários)
  -u, --user NOME     usuário que fez o login (mesmo depois de sudo/su)
  -s, --since QUANDO  30m, 2h, 7d ou "2026-10-04 13:00"
      --until QUANDO
  -l, --level NIVEL   info, notice, warn, alert (mínimo)
  -g, --grep TEXTO
      --ses N         tudo de uma sessão de login
  -n N                só os últimos N
  -f, --follow        acompanha em tempo real
      --json          saída JSON (uma linha por evento)

OPÇÕES DO report:
  -s, --since QUANDO  início do período (padrão: 24h)
      --until QUANDO
  -n N                quantos itens em cada ranking (padrão: 10)
      --json          relatório em JSON

Config padrão: /etc/loger/loger.toml (opcional)
`

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "loger: "+format+"\n", a...)
	os.Exit(2)
}

func opt(args []string, short, long string) (string, bool) {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == short || args[i] == long {
			return args[i+1], true
		}
	}
	return "", false
}

func loadConfig(args []string) *config.Config {
	path, explicit := opt(args, "-c", "--config")
	if !explicit {
		path = config.DefaultPath
	}
	c, err := config.Load(path, explicit)
	if err != nil {
		die("%v", err)
	}
	return c
}

func logDir(args []string, c *config.Config) string {
	if d, ok := opt(args, "-d", "--dir"); ok {
		return d
	}
	return c.Log.Dir
}

func main() {
	cmd := "help"
	var rest []string
	if len(os.Args) > 1 {
		cmd, rest = os.Args[1], os.Args[2:]
	}
	// No container a raiz do host vem montada em LOGER_ROOT: o chroot faz /etc, /home, o
	// journal e o journalctl serem os do host, sem trocar nenhum caminho do código.
	if root := os.Getenv("LOGER_ROOT"); root != "" && root != "/" {
		if err := unix.Chroot(root); err != nil {
			die("chroot %s: %v", root, err)
		}
		os.Chdir("/")
	}
	welcome()
	switch cmd {
	case "daemon":
		path, explicit := opt(rest, "-c", "--config")
		if !explicit {
			path = config.DefaultPath
		}
		opts := daemon.Options{ConfigPath: path, Explicit: explicit, Version: version}
		if err := daemon.Run(loadConfig(rest), opts); err != nil {
			die("%v", err)
		}
	case "show":
		dir := logDir(rest, loadConfig(rest))
		f, err := show.Parse(rest)
		if err != nil {
			die("%v", err)
		}
		if err := show.Show(dir, f); err != nil {
			die("%v", err)
		}
	case "report":
		dir := logDir(rest, loadConfig(rest))
		o, err := report.Parse(rest)
		if err != nil {
			die("%v", err)
		}
		rep, err := report.Build(dir, o)
		if err != nil {
			die("%v (rode como root?)", err)
		}
		if o.JSON {
			b, _ := json.MarshalIndent(rep, "", "  ")
			fmt.Println(string(b))
		} else {
			report.Print(os.Stdout, rep)
		}
	case "verify":
		verify(rest)
	case "receive":
		if err := remote.Receive(loadConfig(rest)); err != nil {
			die("%v", err)
		}
	case "keygen":
		fmt.Println(remote.Keygen())
	case "config":
		fmt.Print(config.Sample)
	case "version", "--version", "-V":
		fmt.Println("loger", version)
	case "help", "--help", "-h":
		fmt.Print(help)
	default:
		die("comando desconhecido: %s (veja `loger help`)", cmd)
	}
}

func verify(args []string) {
	dir := logDir(args, loadConfig(args))
	rep, err := store.Verify(dir)
	if err != nil {
		die("%v (rode como root?)", err)
	}
	fmt.Printf("%d registros conferidos em %s\n", rep.Records, dir)
	if rep.HasFirst && rep.FirstSeq > 0 {
		if rep.RotatedFiles == 0 {
			rep.Problems = append([]string{fmt.Sprintf(
				"os registros 0 a %d não existem e não houve rotação: o log foi apagado ou truncado", rep.FirstSeq-1)}, rep.Problems...)
		} else {
			fmt.Printf("obs: o registro mais antigo é o seq %d (os anteriores podem ter saído pela rotação)\n", rep.FirstSeq)
		}
	}
	if len(rep.Problems) == 0 {
		fmt.Println("OK: nenhum registro alterado, removido ou inserido.")
		return
	}
	fmt.Printf("PROBLEMAS ENCONTRADOS (%d):\n", len(rep.Problems))
	for _, p := range rep.Problems {
		fmt.Println("  -", p)
	}
	os.Exit(1)
}
