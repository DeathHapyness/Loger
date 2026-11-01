package util

import "testing"

func TestJoinArgv(t *testing.T) {
	argv := []string{"/bin/echo", `aspas "x" \ barra`, "ção ü 日本", "tab\tnl\nctl\x01\x7f", "<html>&amp;", " ", "", "it's"}
	want := `/bin/echo 'aspas "x" \ barra' 'ção ü 日本' 'tab` + "\t" + `nl` + "\n" + `ctl` + "\x01\x7f" + `' '<html>&amp;' '` + " " + `' '' 'it'\''s'`
	if got := JoinArgv(argv); got != want {
		t.Fatalf("\n got %q\nwant %q", got, want)
	}
}
