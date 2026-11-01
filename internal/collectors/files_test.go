package collectors

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DeathHapyness/loger/internal/config"
	"github.com/DeathHapyness/loger/internal/event"
)

func newTestWatcher(t *testing.T) (*watcher, chan event.Ev) {
	ctx, ch := testCtx(nil)
	return &watcher{ctx: ctx, wds: map[int]watch{}, watchedDirs: map[string]bool{}, fileTargets: map[string]bool{},
		readTargets: map[string]bool{}, snaps: map[string]snap{}, pending: map[string]*pending{}}, ch
}

func TestDiffAccounts(t *testing.T) {
	w, ch := newTestWatcher(t)
	w.diffAccounts("root:x:0:0::/root:/bin/bash\njoao:x:1000:1000::/home/joao:/bin/bash\nvelho:x:1001:1001::/:/bin/sh\n",
		"root:x:0:0::/root:/bin/bash\njoao:x:0:1000::/home/joao:/bin/bash\nnovo:x:1002:1002::/:/bin/zsh\n")
	evs := drain(ch)
	got := map[string]string{}
	for _, e := range evs {
		got[e.Kind] = e.Level + " " + e.Msg
	}
	if got["account.user_added"] != "alert usuário criado: novo (uid 1002, shell /bin/zsh)" ||
		!strings.HasPrefix(got["account.user_changed"], "alert usuário alterado: joao") ||
		got["account.user_removed"] != "warn usuário removido: velho" || len(evs) != 3 {
		t.Fatalf("%v", got)
	}
}

func TestDiffGroups(t *testing.T) {
	w, ch := newTestWatcher(t)
	w.diffGroups("sudo:x:27:ana\nweb:x:50:\nvelho:x:60:\n", "sudo:x:27:ana,joao\nweb:x:50:joao\nnovo:x:70:\n")
	var msgs []string
	for _, e := range drain(ch) {
		msgs = append(msgs, e.Level+" "+e.Msg)
	}
	want := []string{"alert joao adicionado ao grupo sudo", "notice grupo criado: novo", "notice joao adicionado ao grupo web", "notice grupo removido: velho"}
	if strings.Join(msgs, "|") != strings.Join([]string{want[1], want[0], want[2], want[3]}, "|") {
		t.Fatalf("%q", msgs)
	}
}

// O fingerprint esperado vem do ssh-keygen -lf.
func TestDescribeKey(t *testing.T) {
	ty, fp, c := describeKey(`from="10.0.0.1" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBLpPBlpHXLKl8jVnMzOSPOg2yg0MArz1i5UjodY3HCZ joao@pc`)
	if ty != "ssh-ed25519" || fp != "SHA256:YR/69YIJN6Sf3ebDfqZyImD3Bc6KVkkN9zW1dyll9BY" || c != "joao@pc" {
		t.Fatalf("%s %s %s", ty, fp, c)
	}
}

func TestFilesLive(t *testing.T) {
	dir := t.TempDir()
	etc := filepath.Join(dir, "etc")
	os.MkdirAll(etc, 0o755)
	os.WriteFile(filepath.Join(etc, "hosts"), []byte("a\n"), 0o644)
	keys := filepath.Join(dir, "home", "joao", ".ssh", "authorized_keys")
	c := config.Default()
	c.Files.Watch = []string{filepath.Join(etc, "hosts"), filepath.Join(etc, "cron.d"), keys}
	c.Files.AuthorizedKeys = false
	ctx, ch := testCtx(c)
	go runFiles(ctx)
	waitFor(t, ch, "loger.collector")
	time.Sleep(100 * time.Millisecond)

	// Editor que salva gravando um temporário e renomeando por cima.
	tmp := filepath.Join(etc, ".hosts.swp")
	os.WriteFile(tmp, []byte("a\nb\n"), 0o644)
	os.Rename(tmp, filepath.Join(etc, "hosts"))
	if ev := waitFor(t, ch, "file.modified"); ev.Data.(event.D)["path"] != filepath.Join(etc, "hosts") {
		t.Fatalf("%+v", ev)
	}

	os.Chmod(filepath.Join(etc, "hosts"), 0o666)
	if ev := waitFor(t, ch, "file.perm"); !strings.Contains(ev.Msg, "modo 644 -> 666") {
		t.Fatal(ev.Msg)
	}

	// Diretório-alvo que não existia.
	os.MkdirAll(filepath.Join(etc, "cron.d"), 0o755)
	time.Sleep(100 * time.Millisecond)
	os.WriteFile(filepath.Join(etc, "cron.d", "job"), []byte("* * * * * root x\n"), 0o644)
	if ev := waitFor(t, ch, "file.created"); ev.Level != event.Alert || !strings.HasSuffix(ev.Msg, "cron.d/job criado") {
		t.Fatalf("%+v", ev)
	}

	// Arquivo-alvo dentro de diretórios que ainda não existiam, com análise do conteúdo.
	os.MkdirAll(filepath.Dir(keys), 0o700)
	time.Sleep(100 * time.Millisecond)
	os.WriteFile(keys, []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBLpPBlpHXLKl8jVnMzOSPOg2yg0MArz1i5UjodY3HCZ invasor@x\n"), 0o600)
	ev := waitFor(t, ch, "ssh.key_added")
	if ev.User != "joao" || ev.Data.(event.D)["comment"] != "invasor@x" {
		t.Fatalf("%+v", ev)
	}

	os.Remove(filepath.Join(etc, "hosts"))
	waitFor(t, ch, "file.deleted")
}

// mkdir -p cria as pastas mais rápido do que a vigilância de cada uma começa; o arquivo
// gravado logo depois precisa ser visto mesmo assim.
func TestFilesMkdirRace(t *testing.T) {
	for i := 0; i < 5; i++ {
		dir := t.TempDir()
		keys := filepath.Join(dir, "home", "joao", ".ssh", "authorized_keys")
		cron := filepath.Join(dir, "etc", "cron.d")
		c := config.Default()
		c.Files.Watch = []string{keys, cron}
		c.Files.AuthorizedKeys = false
		ctx, ch := testCtx(c)
		go runFiles(ctx)
		waitFor(t, ch, "loger.collector")
		os.MkdirAll(filepath.Dir(keys), 0o700)
		os.WriteFile(keys, []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBLpPBlpHXLKl8jVnMzOSPOg2yg0MArz1i5UjodY3HCZ x\n"), 0o600)
		os.MkdirAll(cron, 0o755)
		os.WriteFile(filepath.Join(cron, "job"), []byte("x\n"), 0o644)
		time.Sleep(1500 * time.Millisecond)
		evs := drain(ch)
		if countKind(evs, "ssh.key_added") != 1 || countKind(evs, "file.created") != 2 {
			for _, e := range evs {
				t.Logf("%s %s", e.Kind, e.Msg)
			}
			t.Fatalf("rodada %d", i)
		}
	}
}
