package show

import (
	"testing"

	"github.com/DeathHapyness/loger/internal/event"
)

func lines() [][]byte {
	evs := []event.Ev{
		event.New("exec", event.Info, "ls \"a\"").WithUser("joao").WithData(event.D{"ses": 12}),
		event.New("exec.suspicious", event.Alert, "/tmp/x").WithUser("maria").WithData(event.D{"ses": 123}),
		event.New("execve", event.Info, "outro"),
		event.New("ssh.auth_fail", event.Warn, "Falha DE login").WithData(event.D{"ip": "1.2.3.4"}),
		event.New("session.start", event.Notice, "kind\":\"exec").WithUser("joao\\x"),
	}
	var out [][]byte
	for i, e := range evs {
		r := event.FromEv(e, uint64(i), "h", event.Genesis)
		out = append(out, r.Line())
	}
	return out
}

// O filtro rápido nunca pode descartar uma linha que o filtro completo aceitaria.
func TestQuickIsSafe(t *testing.T) {
	cases := [][]string{
		{"-k", "exec"}, {"-k", "ssh,session"}, {"-u", "joao"}, {"-u", "joao\\x"},
		{"-l", "warn"}, {"--ses", "12"}, {"-g", "falha de"}, {"-g", "1.2.3"}, {"-g", "\"a\""},
	}
	for _, args := range cases {
		f, err := Parse(args)
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range lines() {
			r, _ := event.Parse(l)
			if f.Matches(&r) && !f.quick(l) {
				t.Errorf("%v: quick descartou %s", args, l)
			}
		}
	}
}

func TestMatches(t *testing.T) {
	count := func(args ...string) int {
		f, err := Parse(args)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, l := range lines() {
			if _, ok := f.Match(l); ok {
				n++
			}
		}
		return n
	}
	checks := []struct {
		args []string
		want int
	}{
		{[]string{"-k", "exec"}, 2},
		{[]string{"--ses", "12"}, 1},
		{[]string{"-l", "warn"}, 2},
		{[]string{"-u", "joao"}, 1},
		{[]string{"-g", "falha de"}, 1},
		{[]string{"-g", "1.2.3"}, 1},
	}
	for _, c := range checks {
		if got := count(c.args...); got != c.want {
			t.Errorf("%v: %d, esperado %d", c.args, got, c.want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	for _, args := range [][]string{{"-n"}, {"-n", "x"}, {"--ses", "a"}, {"-s", "ontem"}, {"--xyz"}} {
		if _, err := Parse(args); err == nil {
			t.Errorf("%v aceito", args)
		}
	}
}
