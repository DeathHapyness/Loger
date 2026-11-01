package sockets

import (
	"fmt"
	"net"
	"os"
	"sort"
	"testing"
)

func keys(socks []Sock) []string {
	var out []string
	for _, s := range socks {
		if s.Proto == "tcp" && s.State == Listen || s.Proto == "udp" {
			out = append(out, fmt.Sprintf("%s/%s:%d>%s:%d %d", s.Proto, s.Local, s.LocalPort, s.Remote, s.RemotePort, s.Inode))
		}
	}
	sort.Strings(out)
	return out
}

// sock_diag e /proc/net precisam enxergar os mesmos sockets.
func TestDiagMatchesProc(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	diag, err := readDiag(Kind{Listen: true, Established: true, UDP: true})
	if err != nil {
		t.Skipf("sock_diag indisponível: %v", err)
	}
	d, p := keys(diag), keys(readProc(Kind{Listen: true, Established: true, UDP: true}))
	if fmt.Sprint(d) != fmt.Sprint(p) {
		t.Fatalf("diferença\ndiag %v\nproc %v", d, p)
	}
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	found := false
	for _, s := range diag {
		found = found || (s.State == Listen && s.LocalPort == port && s.Local == "127.0.0.1")
	}
	if !found {
		t.Fatal("porta de teste não encontrada")
	}
}

func TestTCPPeerOf(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	peer, ok := TCPPeerOf(os.Getpid())
	if !ok || (peer != l.Addr().String() && peer != c.LocalAddr().String()) {
		t.Fatalf("peer = %q", peer)
	}
}

func TestParseProcAddr(t *testing.T) {
	cases := map[string]string{
		"0100007F:0016":                         "127.0.0.1:22",
		"0000000000000000FFFF00000100007F:0050": "127.0.0.1:80",
		"00000000000000000000000001000000:0277": "::1:631",
	}
	for in, want := range cases {
		a, p, ok := parseProcAddr(in)
		if got := fmt.Sprintf("%s:%d", a, p); !ok || got != want {
			t.Errorf("%s: %s", in, got)
		}
	}
}

func TestReadMixed(t *testing.T) {
	all := keys(readProc(Kind{Listen: true, Established: true, UDP: true}))
	got := keys(Read(Kind{Listen: true, UDP: true}))
	if fmt.Sprint(all) != fmt.Sprint(got) {
		t.Fatalf("\nRead %v\nproc %v", got, all)
	}
	for _, s := range Read(Kind{Listen: true}) {
		if s.Proto != "tcp" || s.State != Listen {
			t.Fatalf("socket inesperado: %+v", s)
		}
	}
}
