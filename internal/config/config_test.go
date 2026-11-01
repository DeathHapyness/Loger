package config

import (
	"strings"
	"testing"
)

func TestSampleParses(t *testing.T) {
	c, err := Parse([]byte(Sample))
	if err != nil {
		t.Fatal(err)
	}
	if c.Log.Keep != 20 || len(c.Files.Watch) != len(Default().Files.Watch) {
		t.Fatalf("valores inesperados: %+v", c.Log)
	}
}

func TestPartialKeepsDefaults(t *testing.T) {
	c, err := Parse([]byte("[log]\nkeep = 3\n[net]\nlisten = false\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Log.Keep != 3 || c.Log.MaxSizeMB != 50 || c.Net.Listen || !c.Net.Outbound || c.Auth.BruteforceThreshold != 10 {
		t.Fatalf("padrões perdidos: %+v %+v", c.Log, c.Net)
	}
}

func TestUnknownField(t *testing.T) {
	if _, err := Parse([]byte("[log]\nkep = 3\n")); err == nil {
		t.Fatal("campo desconhecido aceito")
	}
}

func TestErrorMessages(t *testing.T) {
	_, err := Parse([]byte("[log]\nkeep = 1\nkep = 3\n"))
	if err == nil || err.Error() != "campo desconhecido: log.kep (linha 3)" {
		t.Fatalf("%v", err)
	}
	_, err = Parse([]byte("[log]\nkeep = \"x\"\n"))
	if err == nil || err.Error()[:7] != "linha 2" {
		t.Fatalf("%v", err)
	}
}

func TestIgnoreRules(t *testing.T) {
	c, err := Parse([]byte("[exec]\nignore_exe = [\"/bin/x\"]\n[[exec.ignore]]\nexe = \"/usr/lib/*/a\"\n[[exec.ignore]]\nuser = \"backup\"\nargv = \"*rsync*\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Exec.Ignore) != 2 || c.Exec.Ignore[1].User != "backup" || c.Exec.IgnoreExe[0] != "/bin/x" {
		t.Fatalf("%+v", c.Exec)
	}
	for _, bad := range []string{"[[exec.ignore]]\n", "[[exec.ignore]]\nexe = \"/a[\"\n", "[[exec.ignore]]\nexe = \"x\"\ncmd = \"y\"\n"} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("aceito: %q", bad)
		}
	}
}

func TestSampleIgnoreExampleParses(t *testing.T) {
	text := strings.NewReplacer("# [[exec.ignore]]", "[[exec.ignore]]", "# exe =", "exe =", "# user =", "user =", "# parent =", "parent =", "# argv =", "argv =").Replace(Sample)
	c, err := Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Exec.Ignore) != 3 {
		t.Fatalf("%d regras", len(c.Exec.Ignore))
	}
}
