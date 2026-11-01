package main

import (
	"fmt"
	"os"
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

Config padrão: /etc/loger/loger.toml (opcional)
`

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "loger: "+format+"\n", a...)
	os.Exit(2)
}

func main() {
	cmd := "help"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "version", "--version", "-V":
		fmt.Println("loger", version)
	case "help", "--help", "-h":
		fmt.Print(help)
	default:
		die("comando desconhecido: %s (veja `loger help`)", cmd)
	}
}
