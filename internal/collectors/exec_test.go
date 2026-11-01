package collectors

import (
	"encoding/binary"
	"os/exec"
	"slices"
	"testing"
	"time"

	"github.com/DeathHapyness/loger/internal/config"
	"github.com/DeathHapyness/loger/internal/event"
	"github.com/DeathHapyness/loger/internal/procfs"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		exe  string
		argv []string
		kind string
	}{
		{"/tmp/x", nil, "exec.suspicious"},
		{"/dev/shm/a/b", nil, "exec.suspicious"},
		{"/usr/bin/sudo", nil, "priv.cmd"},
		{"/usr/bin/nc.openbsd", []string{"nc", "-l"}, "exec.net_tool"},
		{"", []string{"/usr/sbin/useradd", "x"}, "account.cmd"},
		{"/usr/bin/ls", []string{"ls"}, "exec"},
	}
	for _, c := range cases {
		if kind, _ := classify(procfs.Info{Exe: c.exe, Argv: c.argv}); kind != c.kind {
			t.Errorf("%s %v: %s", c.exe, c.argv, kind)
		}
	}
}

func TestFmtDur(t *testing.T) {
	for secs, want := range map[int64]string{5: "5s", 65: "1m5s", 3725: "1h2m"} {
		if got := fmtDur(secs); got != want {
			t.Errorf("%d: %s", secs, got)
		}
	}
}

func procEvent(what uint32, fields ...uint32) []byte {
	b := make([]byte, nlmsgHdrLen+cnMsgLen+procEventHeaderLen+len(fields)*4+8)
	binary.NativeEndian.PutUint32(b, uint32(len(b)))
	off := nlmsgHdrLen + cnMsgLen
	binary.NativeEndian.PutUint32(b[off:], what)
	for i, f := range fields {
		binary.NativeEndian.PutUint32(b[off+procEventHeaderLen+i*4:], f)
	}
	return b
}

// startChild inicia um processo que fica vivo (sh com dois comandos não vira exec do sleep).
func startChild(t *testing.T, args ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(args[0], args[1:]...)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	time.Sleep(50 * time.Millisecond)
	return cmd
}

func TestDatagramExecExit(t *testing.T) {
	c := config.Default()
	c.Exec.OnlySessions = false
	ctx, ch := testCtx(c)
	tr := newTracker(ctx)
	cmd := startChild(t, "/bin/sh", "-c", "sleep 30; true", "ção 'x'")
	pid := uint32(cmd.Process.Pid)
	handleDatagram(tr, append(procEvent(procEvExec, pid, pid), procEvent(procEvExit, pid, pid, 0, 0)...))
	evs := drain(ch)
	if len(evs) != 1 || evs[0].Kind != "exec" {
		t.Fatalf("%+v", evs)
	}
	d := evs[0].Data.(event.D)
	wantArgv := []string{"/bin/sh", "-c", "sleep 30; true", "ção 'x'"}
	wantMsg := `/bin/sh -c 'sleep 30; true' 'ção '\''x'\'''`
	if !slices.Equal(d["argv"].([]string), wantArgv) || evs[0].Msg != wantMsg {
		t.Fatalf("%q %v", evs[0].Msg, d["argv"])
	}
	if d["ses"] != nil || len(d["tags"].([]string)) != 0 {
		t.Fatalf("%+v", d)
	}
	if _, ok := tr.procs[int(pid)]; ok {
		t.Fatal("exit não removeu o processo")
	}
}

// Com only_sessions, comandos fora de sessão não viram evento, mas o processo continua
// sendo acompanhado (necessário para detectar escalada de privilégio).
func TestOutOfSessionLight(t *testing.T) {
	ctx, ch := testCtx(nil)
	tr := newTracker(ctx)
	cmd := startChild(t, "/bin/sh", "-c", "sleep 30; true")
	pid := cmd.Process.Pid
	if a, s := procfs.LoginIDs(pid); validSession(a, s) {
		t.Skip("o teste roda dentro de uma sessão de login")
	}
	tr.onExec(pid)
	if evs := drain(ch); len(evs) != 0 {
		t.Fatalf("evento gerado fora de sessão: %+v", evs)
	}
	p := tr.procs[pid]
	if p == nil || p.exe == "" || p.start == 0 || p.argv != nil {
		t.Fatalf("%+v", p)
	}
}

func TestIgnoreRulesApplied(t *testing.T) {
	c := config.Default()
	c.Exec.OnlySessions = false
	c.Exec.Ignore = []config.IgnoreRule{{Argv: "*--ignorar-isto*"}}
	ctx, ch := testCtx(c)
	tr := newTracker(ctx)
	a := startChild(t, "/bin/sh", "-c", "sleep 30; true", "--ignorar-isto")
	b := startChild(t, "/bin/sh", "-c", "sleep 31; true")
	tr.onExec(a.Process.Pid)
	tr.onExec(b.Process.Pid)
	evs := drain(ch)
	if len(evs) != 1 || evs[0].Msg != "/bin/sh -c 'sleep 31; true'" {
		t.Fatalf("%+v", evs)
	}
}

func TestConnectorLive(t *testing.T) {
	fd, err := openConnector()
	if err != nil {
		t.Skipf("proc connector indisponível: %v", err)
	}
	c := config.Default()
	c.Exec.OnlySessions = false
	ctx, ch := testCtx(c)
	go runConnector(newTracker(ctx), fd)
	time.Sleep(100 * time.Millisecond)
	go exec.Command("/bin/sh", "-c", "sleep 0.5; true", "loger-teste-ao-vivo").Run()
	want := "/bin/sh -c 'sleep 0.5; true' loger-teste-ao-vivo"
	deadline := time.After(5 * time.Second)
	for {
		select {
		case ev := <-ch:
			if ev.Kind == "exec" && ev.Msg == want {
				return
			}
		case <-deadline:
			t.Fatal("exec não recebido pelo proc connector")
		}
	}
}
