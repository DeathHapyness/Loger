package main

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const banner = "\n" +
	"    __\n" +
	"   / /   ____  ____ _____ ____  _____\n" +
	"  / /   / __ \\/ __ `/ __ `/ _ \\/ ___/\n" +
	" / /___/ /_/ / /_/ / /_/ /  __/ /\n" +
	"/_____/\\____/\\__, /\\__, /\\___/_/\n" +
	"            /____//____/\n" +
	"\n"

// welcome mostra o banner só na primeira execução do usuário e só em terminal,
// para não aparecer em pipes, no --json nem no journal do systemd.
func welcome() {
	if _, err := unix.IoctlGetTermios(int(os.Stderr.Fd()), unix.TCGETS); err != nil {
		return
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return
	}
	mark := filepath.Join(base, "loger", ".welcome")
	if _, err := os.Stat(mark); err == nil {
		return
	}
	if os.MkdirAll(filepath.Dir(mark), 0o700) != nil {
		return
	}
	if f, err := os.OpenFile(mark, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600); err == nil {
		f.Close()
		fmt.Fprintf(os.Stderr, "%s  auditoria leve para servidores Linux — versão %s\n  comece com: loger help\n\n", banner, version)
	}
}
