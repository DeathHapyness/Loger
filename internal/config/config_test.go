package config

import "testing"

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
