package collectors

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/DeathHapyness/loger/internal/config"
	"github.com/DeathHapyness/loger/internal/sockets"
)

func TestSocketOwners(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	var target sockets.Sock
	for _, s := range sockets.Read(sockets.Kind{Listen: true}) {
		if s.LocalPort == port {
			target = s
		}
	}
	if target.Inode == 0 {
		t.Fatal("socket de teste não encontrado")
	}
	got := socketOwners(map[uint64]uint32{target.Inode: target.UID}, true)
	if got[target.Inode] != os.Getpid() {
		t.Fatalf("dono = %d, esperado %d", got[target.Inode], os.Getpid())
	}
	// uid errado: a varredura filtrada não acha, a completa sim.
	got = socketOwners(map[uint64]uint32{target.Inode: 54321}, false)
	if got[target.Inode] != os.Getpid() && os.Getuid() != 0 {
		t.Fatalf("fallback falhou: %v", got)
	}
}

func TestIsListener(t *testing.T) {
	cases := []struct {
		s    sockets.Sock
		want bool
	}{
		{sockets.Sock{Proto: "tcp", State: sockets.Listen, LocalPort: 22}, true},
		{sockets.Sock{Proto: "tcp", State: sockets.Established, LocalPort: 22}, false},
		{sockets.Sock{Proto: "udp", LocalPort: 53}, true},
		{sockets.Sock{Proto: "udp", LocalPort: 40000}, false},
		{sockets.Sock{Proto: "udp", LocalPort: 53, RemotePort: 9}, false},
	}
	for _, c := range cases {
		if got := isListener(c.s, 32768, 60999); got != c.want {
			t.Errorf("%+v: %v", c.s, got)
		}
	}
}

func TestNetListenLive(t *testing.T) {
	c := config.Default()
	c.Net.IntervalMs = 200
	ctx, ch := testCtx(c)
	go runNet(ctx)
	waitFor(t, ch, "net.inventory")
	// As portas do próprio processo são ignoradas, então quem escuta é um filho.
	cmd := exec.Command("python3", "-c", "import socket,time; s=socket.socket(); s.bind(('127.0.0.1',47124)); s.listen(); time.sleep(1.5)")
	if err := cmd.Start(); err != nil {
		t.Skip("python3 indisponível")
	}
	ev := waitFor(t, ch, "net.listen")
	if ev.Data.(map[string]any)["port"] != uint16(47124) || !strings.Contains(ev.Msg, fmt.Sprintf("pid %d", cmd.Process.Pid)) {
		t.Fatalf("%+v", ev)
	}
	cmd.Wait()
	waitFor(t, ch, "net.listen_closed")
}
