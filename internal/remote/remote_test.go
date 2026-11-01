package remote

import (
	"bytes"
	"encoding/binary"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DeathHapyness/loger/internal/event"
	"github.com/DeathHapyness/loger/internal/store"
)

func TestFrameRoundtrip(t *testing.T) {
	c, err := ParseKey(Keygen())
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	writeFrame(&buf, c, []byte("olá"))
	if got := binary.BigEndian.Uint32(buf.Bytes()); int(got) != buf.Len()-4 {
		t.Fatalf("tamanho %d", got)
	}
	plain, err := readFrame(bytes.NewReader(buf.Bytes()), c)
	if err != nil || string(plain) != "olá" {
		t.Fatalf("%q %v", plain, err)
	}
	other, _ := ParseKey(Keygen())
	if _, err := readFrame(bytes.NewReader(buf.Bytes()), other); err != errAuth {
		t.Fatalf("chave errada aceita: %v", err)
	}
	tampered := bytes.Clone(buf.Bytes())
	tampered[len(tampered)-1] ^= 1
	if _, err := readFrame(bytes.NewReader(tampered), c); err != errAuth {
		t.Fatalf("quadro alterado aceito: %v", err)
	}
	huge := []byte{0x7f, 0, 0, 0}
	if _, err := readFrame(bytes.NewReader(huge), c); err != errBadFrame {
		t.Fatalf("tamanho absurdo aceito: %v", err)
	}
}

func TestParseKey(t *testing.T) {
	for _, k := range []string{"", "abc", strings.Repeat("z", 64), strings.Repeat("a", 62)} {
		if _, err := ParseKey(k); err == nil {
			t.Errorf("%q aceita", k)
		}
	}
}

func TestSafeHost(t *testing.T) {
	cases := map[string]string{"srv-1.local": "srv-1.local", "../../etc": "_.._etc", "": "_", "a/b": "a_b", "çã": "__", "..": "_"}
	for in, want := range cases {
		if got := safeHost(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
}

func TestReceiverChain(t *testing.T) {
	dir := t.TempDir()
	r := &receiver{dir: dir, maxMB: 1, keep: 2, hosts: map[string]*hostState{}}
	st, err := r.host("h")
	if err != nil {
		t.Fatal(err)
	}
	prev := event.Genesis
	var lines [][]byte
	for i := 0; i < 5; i++ {
		rec := event.FromEv(event.New("exec", event.Info, "x"), uint64(i), "h", prev)
		prev = rec.Hash
		lines = append(lines, rec.Line())
	}
	kinds := func(evs []event.Ev) string {
		var k []string
		for _, e := range evs {
			k = append(k, e.Kind)
		}
		return strings.Join(k, ",")
	}
	for _, l := range lines[:2] {
		if evs := r.store(st, "h", l, false); len(evs) != 0 {
			t.Fatalf("%v", kinds(evs))
		}
	}
	if k := kinds(r.store(st, "h", lines[3], false)); k != "remote.chain_gap" {
		t.Fatalf("gap: %s", k)
	}
	if k := kinds(r.store(st, "h", lines[0], false)); k != "remote.chain_reset" {
		t.Fatalf("reset: %s", k)
	}
	bad := bytes.Replace(lines[4], []byte(`"msg":"x"`), []byte(`"msg":"y"`), 1)
	if k := kinds(r.store(st, "h", bad, false)); k != "remote.bad_record" {
		t.Fatalf("hash: %s", k)
	}
	st.silent = true
	if k := kinds(r.store(st, "h", []byte(`{"heartbeat":true}`), true)); k != "remote.host_back" {
		t.Fatalf("volta: %s", k)
	}
	st.file.Sync()
	if files := store.LogFiles(filepath.Join(dir, "h")); len(files) != 1 {
		t.Fatalf("%v", files)
	}
}
