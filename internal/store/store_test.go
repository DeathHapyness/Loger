package store

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DeathHapyness/loger/internal/event"
)

func fill(t *testing.T, dir string, n int) *Store {
	t.Helper()
	s, err := Open(dir, 1, 3, false, "h")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if _, err := s.Append(event.New("exec", event.Info, fmt.Sprintf("cmd %d", i))); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func TestVerifyOK(t *testing.T) {
	dir := t.TempDir()
	fill(t, dir, 50)
	rep, err := Verify(dir)
	if err != nil || len(rep.Problems) != 0 || rep.Records != 50 {
		t.Fatalf("%v %+v", err, rep)
	}
}

func TestReopenContinuesChain(t *testing.T) {
	dir := t.TempDir()
	fill(t, dir, 5).Log.Close()
	s := fill(t, dir, 5)
	if s.LastKind != "exec" {
		t.Fatalf("LastKind = %q", s.LastKind)
	}
	rep, _ := Verify(dir)
	if len(rep.Problems) != 0 || rep.Records != 10 {
		t.Fatalf("%+v", rep)
	}
}

func TestVerifyDetectsEdit(t *testing.T) {
	dir := t.TempDir()
	fill(t, dir, 10)
	p := filepath.Join(dir, Base)
	b, _ := os.ReadFile(p)
	os.WriteFile(p, []byte(strings.Replace(string(b), "cmd 4", "cmd X", 1)), 0o600)
	rep, _ := Verify(dir)
	if len(rep.Problems) != 1 || !strings.Contains(rep.Problems[0], "seq 4 foi ALTERADO") {
		t.Fatalf("%v", rep.Problems)
	}
}

func TestVerifyDetectsRemoval(t *testing.T) {
	dir := t.TempDir()
	fill(t, dir, 10)
	p := filepath.Join(dir, Base)
	b, _ := os.ReadFile(p)
	lines := strings.SplitAfter(string(b), "\n")
	os.WriteFile(p, []byte(strings.Join(append(lines[:3], lines[4:]...), "")), 0o600)
	rep, _ := Verify(dir)
	if len(rep.Problems) != 1 || !strings.Contains(rep.Problems[0], "corrente quebrada entre seq 2 e seq 4") {
		t.Fatalf("%v", rep.Problems)
	}
}

func TestRotation(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, 1, 2, false, "h")
	big := strings.Repeat("x", 100*1024)
	for i := 0; i < 40; i++ {
		s.Append(event.New("exec", event.Info, big))
	}
	files := LogFiles(dir)
	if len(files) != 3 || filepath.Base(files[0]) != Base+".2" || filepath.Base(files[2]) != Base {
		t.Fatalf("arquivos: %v", files)
	}
	rep, _ := Verify(dir)
	if len(rep.Problems) != 0 || rep.FirstSeq == 0 || rep.RotatedFiles != 2 {
		t.Fatalf("%+v", rep)
	}
}

func TestTamper(t *testing.T) {
	dir := t.TempDir()
	s := fill(t, dir, 3)
	if _, bad := s.Tick(); bad {
		t.Fatal("falso positivo")
	}
	os.Remove(filepath.Join(dir, Base))
	ev, bad := s.Tick()
	if !bad || ev.Kind != "loger.log_tampered" {
		t.Fatal("remoção não detectada")
	}
	s.Append(event.New("exec", event.Info, "depois"))
	if _, err := os.Stat(filepath.Join(dir, Base)); err != nil {
		t.Fatal("arquivo novo não criado")
	}
}

func TestEachLineReverse(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	var want []string
	var sb strings.Builder
	for i := 0; i < 5000; i++ {
		l := fmt.Sprintf("linha %d %s", i, strings.Repeat("y", i%97))
		want = append(want, l)
		sb.WriteString(l + "\n")
	}
	os.WriteFile(p, []byte(sb.String()+"sem quebra"), 0o600)
	want = append(want, "sem quebra")
	var got []string
	EachLineReverse(p, func(l []byte) bool {
		got = append(got, string(l))
		return true
	})
	if len(got) != len(want) {
		t.Fatalf("%d linhas, esperado %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[len(want)-1-i] {
			t.Fatalf("linha %d: %q", i, got[i])
		}
	}
}
