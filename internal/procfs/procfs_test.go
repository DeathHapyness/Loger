package procfs

import (
	"os"
	"slices"
	"testing"
)

func TestReadSelf(t *testing.T) {
	p, ok := Read(os.Getpid(), 4096)
	if !ok {
		t.Fatal("não leu o próprio processo")
	}
	exe, _ := os.Executable()
	if p.Exe != exe || p.PPID != os.Getppid() || p.UID != uint32(os.Getuid()) || p.Start == 0 {
		t.Fatalf("%+v", p)
	}
	if len(p.Argv) == 0 || p.Argv[0] != os.Args[0] {
		t.Fatalf("argv %v", p.Argv)
	}
	if !slices.Contains(AllPIDs(), os.Getpid()) {
		t.Fatal("pid ausente em AllPIDs")
	}
	if s, ok := StartTime(os.Getpid()); !ok || s != p.Start {
		t.Fatal("StartTime diferente")
	}
}

func TestArgvTruncated(t *testing.T) {
	v := Argv(os.Getpid(), 3)
	if v[len(v)-1] != "…(truncado)" {
		t.Fatalf("%v", v)
	}
}

func TestGone(t *testing.T) {
	if _, ok := Read(1<<30, 100); ok {
		t.Fatal("pid inexistente lido")
	}
}

func TestTTY(t *testing.T) {
	cases := map[uint64]string{0: "", 136<<8 | 3: "pts/3", 4<<8 | 1: "tty1", 4<<8 | 65: "ttyS1"}
	for nr, want := range cases {
		if got := ttyName(nr); got != want {
			t.Errorf("%d: %q", nr, got)
		}
	}
}
