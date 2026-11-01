package collectors

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DeathHapyness/loger/internal/config"
	"github.com/DeathHapyness/loger/internal/event"
)

func parseAuth(lines ...string) []event.Ev {
	c := config.Default()
	c.Auth.BruteforceThreshold = 3
	ctx, ch := testCtx(c)
	p := newAuthParser(ctx)
	for _, l := range lines {
		p.line(l)
	}
	return drain(ch)
}

func TestAcceptedKey(t *testing.T) {
	ev := parseAuth("Oct  4 12:00:01 srv sshd-session[123]: Accepted publickey for joao from 10.0.0.9 port 51234 ssh2: ED25519 SHA256:AbCd")
	if len(ev) != 1 || ev[0].Kind != "ssh.auth_ok" || ev[0].User != "joao" {
		t.Fatalf("%+v", ev)
	}
	d := ev[0].Data.(event.D)
	if d["key"] != "ED25519 SHA256:AbCd" || d["ip"] != "10.0.0.9" || d["port"] != "51234" {
		t.Fatalf("%+v", d)
	}
	if ev[0].Msg != "login SSH aceito de 10.0.0.9:51234 via publickey (chave ED25519 SHA256:AbCd)" {
		t.Fatal(ev[0].Msg)
	}
}

func TestBruteforce(t *testing.T) {
	l := "2026-10-04T12:00:01.000000-03:00 srv sshd[9]: Failed password for invalid user admin from 1.2.3.4 port 22 ssh2"
	ev := parseAuth(l, l, l, l, l)
	if countKind(ev, "ssh.auth_fail") != 3 || countKind(ev, "ssh.bruteforce") != 1 || ev[0].User != "admin" {
		t.Fatalf("%+v", ev)
	}
	if ev[0].Msg != "falha de login SSH (password) de 1.2.3.4:22 — usuário inexistente" {
		t.Fatal(ev[0].Msg)
	}
}

func TestSudoDenied(t *testing.T) {
	ev := parseAuth("Oct  4 12:00:01 srv sudo[5]:    maria : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/maria ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow")
	if len(ev) != 1 || ev[0].Kind != "priv.sudo_denied" || ev[0].User != "maria" {
		t.Fatalf("%+v", ev)
	}
	if ev[0].Msg != "sudo NEGADO (user NOT in sudoers): /usr/bin/cat /etc/shadow" {
		t.Fatal(ev[0].Msg)
	}
}

func TestSuFail(t *testing.T) {
	ev := parseAuth("Oct  4 12:00:01 srv su[7]: FAILED SU (to root) joao on pts/0")
	if len(ev) != 1 || ev[0].Kind != "priv.su_fail" {
		t.Fatalf("%+v", ev)
	}
}

func TestTailFollowsRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	os.WriteFile(path, []byte("Oct  4 12:00:00 srv sshd[1]: Accepted password for velho from 1.1.1.1 port 1 ssh2\n"), 0o600)
	ctx, ch := testCtx(nil)
	go tailFile(path, newAuthParser(ctx))
	time.Sleep(200 * time.Millisecond)

	appendLine := func(user string) {
		f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
		f.WriteString("Oct  4 12:00:01 srv sshd[1]: Accepted password for " + user + " from 1.1.1.1 port 1 ssh2\n")
		f.Close()
	}
	start := time.Now()
	appendLine("ana")
	if ev := waitFor(t, ch, "ssh.auth_ok"); ev.User != "ana" {
		t.Fatalf("leu %s (devia começar do fim do arquivo)", ev.User)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("demorou %v: inotify não acordou", time.Since(start))
	}

	os.Rename(path, path+".1")
	appendLine("bia")
	if ev := waitFor(t, ch, "ssh.auth_ok"); ev.User != "bia" {
		t.Fatalf("depois da rotação: %s", ev.User)
	}

	os.Truncate(path, 0)
	appendLine("caio")
	if ev := waitFor(t, ch, "ssh.auth_ok"); ev.User != "caio" {
		t.Fatalf("depois do truncamento: %s", ev.User)
	}

	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString("Oct  4 12:00:01 srv sshd[1]: Accepted password for du")
	time.Sleep(300 * time.Millisecond)
	f.WriteString("da from 1.1.1.1 port 1 ssh2\n")
	f.Close()
	if ev := waitFor(t, ch, "ssh.auth_ok"); ev.User != "duda" {
		t.Fatalf("linha escrita em duas partes: %s", ev.User)
	}
}
