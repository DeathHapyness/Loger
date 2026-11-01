package report

import (
	"testing"

	"github.com/DeathHapyness/loger/internal/event"
	"github.com/DeathHapyness/loger/internal/store"
)

func TestBuild(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir, 10, 2, false, "h")
	if err != nil {
		t.Fatal(err)
	}
	evs := []event.Ev{
		event.New("ssh.auth_fail", event.Notice, "falha").WithUser("root").WithData(event.D{"ip": "10.0.0.9"}),
		event.New("ssh.auth_fail", event.Notice, "falha").WithUser("admin").WithData(event.D{"ip": "10.0.0.9"}),
		event.New("ssh.auth_fail", event.Notice, "falha").WithUser("root").WithData(event.D{"ip": "10.0.0.7"}),
		event.New("ssh.bruteforce", event.Alert, "força bruta de 10.0.0.9").WithData(event.D{"ip": "10.0.0.9"}),
		event.New("ssh.auth_ok", event.Info, "ok").WithUser("ana").WithData(event.D{"ip": "10.0.0.2", "method": "publickey"}),
		event.New("session.start", event.Notice, "login").WithUser("ana").WithData(event.D{"via": "sshd", "from": "10.0.0.2"}),
		event.New("exec", event.Info, "cmd").WithUser("ana").WithData(event.D{"exe": "/usr/bin/ls"}),
		event.New("priv.cmd", event.Notice, "sudo").WithUser("ana").WithData(event.D{"exe": "/usr/bin/sudo"}),
		event.New("net.connect", event.Info, "saída").WithUser("ana").WithData(event.D{"remote": "1.1.1.1", "remote_port": 443}),
		event.New("loger.stop", event.Warn, "parado"),
	}
	for _, ev := range evs {
		if _, err := st.Append(ev); err != nil {
			t.Fatal(err)
		}
	}
	st.Log.Close()

	o, err := Parse([]string{"-s", "1h", "-n", "1"})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Build(dir, o)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Records != len(evs) || rep.AlertCount != 1 || len(rep.Bruteforce) != 1 {
		t.Fatalf("contagens erradas: %+v", rep)
	}
	if len(rep.FailIPs) != 1 || rep.FailIPs[0] != (Count{"10.0.0.9", 2}) {
		t.Fatalf("FailIPs = %v", rep.FailIPs)
	}
	if rep.FailUsers[0] != (Count{"root", 2}) {
		t.Fatalf("FailUsers = %v", rep.FailUsers)
	}
	if rep.Logins[0].Key != "ana via sshd de 10.0.0.2" || rep.SSHAccepts[0].Key != "ana de 10.0.0.2 (publickey)" {
		t.Fatalf("logins = %v %v", rep.Logins, rep.SSHAccepts)
	}
	if rep.Outbound[0].Key != "1.1.1.1:443" || rep.CmdUsers[0] != (Count{"ana", 2}) || len(rep.Integrity) != 1 {
		t.Fatalf("outros = %v %v %v", rep.Outbound, rep.CmdUsers, rep.Integrity)
	}

	o.Until = o.Since
	if rep, err := Build(dir, o); err != nil || rep.Records != 0 {
		t.Fatalf("--until antes dos eventos deveria dar 0 registros: %v %v", rep.Records, err)
	}
}
