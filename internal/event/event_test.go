package event

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func TestRustCompat(t *testing.T) {
	f, err := os.Open("testdata/rust.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		n++
		r, err := Parse(sc.Bytes())
		if err != nil {
			t.Fatalf("linha %d: %v", n, err)
		}
		if got := r.ComputeHash(); got != r.Hash {
			t.Errorf("linha %d: hash %s, esperado %s", n, got, r.Hash)
		}
		if !bytes.Equal(r.Line(), sc.Bytes()) {
			t.Errorf("linha %d: reserialização diferente\n got %s\nwant %s", n, r.Line(), sc.Bytes())
		}
	}
	if n == 0 {
		t.Fatal("fixture vazia")
	}
}

func TestHashSurvivesRoundtrip(t *testing.T) {
	ev := New("exec", Info, "ls -la 'a b' ção ").WithUser("joao").WithData(D{
		"z": 1, "a": []any{1, 2}, "s": "x\"\n\x01\x7f<&>", "n": nil, "u": uint64(1 << 63),
	})
	r := FromEv(ev, 7, "srv", Genesis)
	back, err := Parse(r.Line())
	if err != nil {
		t.Fatal(err)
	}
	if back.ComputeHash() != r.Hash {
		t.Fatal("hash mudou depois do parse")
	}
	want := `{"a":[1,2],"n":null,"s":"x\"\n\u0001` + "\x7f" + `<&>","u":9223372036854775808,"z":1}`
	if string(r.Data) != want {
		t.Fatalf("data = %s", r.Data)
	}
}

func TestOmitEmpty(t *testing.T) {
	r := FromEv(New("loger.stop", Warn, "parado"), 0, "h", Genesis)
	if bytes.Contains(r.Line(), []byte(`"user"`)) || bytes.Contains(r.Line(), []byte(`"data"`)) {
		t.Fatalf("campos vazios gravados: %s", r.Line())
	}
}

func TestSes(t *testing.T) {
	r := FromEv(New("exec", Info, "x").WithData(D{"ses": 12}), 0, "h", Genesis)
	if s, ok := r.Ses(); !ok || s != 12 {
		t.Fatal("ses não encontrado")
	}
	r = FromEv(New("exec", Info, "x").WithData(D{"ses": nil}), 0, "h", Genesis)
	if _, ok := r.Ses(); ok {
		t.Fatal("ses nulo tratado como valor")
	}
}

func TestParseMatchesEncodingJSON(t *testing.T) {
	good := []string{
		`{"seq":1,"ts":"t","host":"h","kind":"k","level":"info","msg":"a\"b\\c\u00e7\ud83d\ude00\n","data":{"x":[1,-2.5e3,true,null,{"y":"}"}]},"prev":"p","hash":"z"}`,
		`{"seq":0,"extra":{"a":[]},"msg":"x"}`,
		` { "seq" : 5 , "msg" : "x" } `,
	}
	for _, l := range good {
		r, err := Parse([]byte(l))
		if err != nil {
			t.Fatalf("%s: %v", l, err)
		}
		var std Record
		if err := json.Unmarshal([]byte(l), &std); err != nil {
			t.Fatal(err)
		}
		std.Data = bytes.TrimSpace(std.Data)
		if r.Seq != std.Seq || r.Msg != std.Msg || r.Kind != std.Kind || !bytes.Equal(r.Data, std.Data) {
			t.Errorf("%s:\n got %+v\nwant %+v", l, r, std)
		}
	}
	bad := []string{``, `{`, `{"seq":-1}`, `{"seq":1.5}`, `{"msg":"a` + "\n" + `"}`, `{"data":{"a":}}`, `{"msg":"x"} lixo`, `{"msg":"x",}`}
	for _, l := range bad {
		if _, err := Parse([]byte(l)); err == nil {
			t.Errorf("%q aceito", l)
		}
	}
}

func TestSesNested(t *testing.T) {
	r := Record{Data: []byte(`{"a":{"ses":9},"process":[{"ses":8}],"ses":3}`)}
	if s, ok := r.Ses(); !ok || s != 3 {
		t.Fatalf("ses = %d %v", s, ok)
	}
	r = Record{Data: []byte(`{"a":{"ses":9}}`)}
	if _, ok := r.Ses(); ok {
		t.Fatal("ses aninhado tratado como do evento")
	}
}
