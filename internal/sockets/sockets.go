package sockets

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"

	"github.com/DeathHapyness/loger/internal/procfs"
	"golang.org/x/sys/unix"
)

const (
	Established = 0x01
	Listen      = 0x0A
)

type Sock struct {
	Proto      string
	Local      string
	LocalPort  uint16
	Remote     string
	RemotePort uint16
	State      uint8
	UID        uint32
	Inode      uint64
}

// Kind diz o que ler. Do TCP só interessam portas em escuta e conexões estabelecidas.
type Kind struct {
	Listen      bool
	Established bool
	UDP         bool
}

var diagBroken atomic.Bool

// Read usa a fonte mais rápida para cada tipo de socket. O sock_diag responde portas em
// escuta e UDP em microssegundos, mas para conexões TCP estabelecidas o kernel percorre a
// tabela inteira uma vez por família e fica mais lento que ler /proc/net/tcp{,6}. Se o
// sock_diag não estiver disponível, tudo vem de /proc/net.
func Read(k Kind) []Sock {
	var out []Sock
	viaDiag := Kind{Listen: k.Listen && !k.Established, UDP: k.UDP}
	viaProc := Kind{Listen: k.Listen && k.Established, Established: k.Established}
	if !diagBroken.Load() && (viaDiag.Listen || viaDiag.UDP) {
		s, err := readDiag(viaDiag)
		if err == nil {
			out = s
		} else {
			diagBroken.Store(true)
		}
	}
	if diagBroken.Load() {
		viaProc = k
	}
	return append(out, readProc(viaProc)...)
}

func addrString(a netip.Addr) string {
	return a.Unmap().String()
}

// ---------------- netlink sock_diag ----------------

const (
	sockDiagByFamily = 20
	reqLen           = 16 + 56
	diagMsgLen       = 72
)

func readDiag(k Kind) ([]Sock, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	var out []Sock
	type query struct {
		proto  uint8
		name   string
		states uint32
	}
	var qs []query
	var tcpStates uint32
	if k.Listen {
		tcpStates |= 1 << Listen
	}
	if k.Established {
		tcpStates |= 1 << Established
	}
	if tcpStates != 0 {
		qs = append(qs, query{unix.IPPROTO_TCP, "tcp", tcpStates})
	}
	if k.UDP {
		qs = append(qs, query{unix.IPPROTO_UDP, "udp", ^uint32(0)})
	}
	buf := make([]byte, 64*1024)
	for _, q := range qs {
		for _, fam := range []uint8{unix.AF_INET, unix.AF_INET6} {
			req := make([]byte, reqLen)
			binary.NativeEndian.PutUint32(req[0:], reqLen)
			binary.NativeEndian.PutUint16(req[4:], sockDiagByFamily)
			binary.NativeEndian.PutUint16(req[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
			req[16] = fam
			req[17] = q.proto
			binary.NativeEndian.PutUint32(req[20:], q.states)
			if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
				return nil, err
			}
			if out, err = recvDump(fd, buf, q.name, out); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

func recvDump(fd int, buf []byte, proto string, out []Sock) ([]Sock, error) {
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, err
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return nil, err
		}
		for _, m := range msgs {
			switch m.Header.Type {
			case unix.NLMSG_DONE:
				return out, nil
			case unix.NLMSG_ERROR:
				code := int32(0)
				if len(m.Data) >= 4 {
					code = int32(binary.NativeEndian.Uint32(m.Data))
				}
				// ENOENT: o kernel não tem diag para este protocolo/família (ex: IPv6 desligado).
				if unix.Errno(-code) == unix.ENOENT {
					return out, nil
				}
				return nil, fmt.Errorf("sock_diag: %v", unix.Errno(-code))
			}
			if len(m.Data) < diagMsgLen {
				continue
			}
			out = append(out, parseDiag(m.Data, proto))
		}
	}
}

func parseDiag(d []byte, proto string) Sock {
	fam := d[0]
	ip := func(off int) netip.Addr {
		if fam == unix.AF_INET {
			return netip.AddrFrom4([4]byte(d[off : off+4]))
		}
		return netip.AddrFrom16([16]byte(d[off : off+16]))
	}
	return Sock{
		Proto:      proto,
		State:      d[1],
		LocalPort:  binary.BigEndian.Uint16(d[4:]),
		RemotePort: binary.BigEndian.Uint16(d[6:]),
		Local:      addrString(ip(8)),
		Remote:     addrString(ip(24)),
		UID:        binary.NativeEndian.Uint32(d[64:]),
		Inode:      uint64(binary.NativeEndian.Uint32(d[68:])),
	}
}

// ---------------- /proc/net ----------------

func parseProcAddr(s string) (string, uint16, bool) {
	h, p, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0, false
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return "", 0, false
	}
	raw, err := hex.DecodeString(h)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return "", 0, false
	}
	// O kernel escreve cada palavra de 32 bits na ordem da máquina.
	for i := 0; i < len(raw); i += 4 {
		binary.NativeEndian.PutUint32(raw[i:], binary.BigEndian.Uint32(raw[i:]))
	}
	var a netip.Addr
	if len(raw) == 4 {
		a = netip.AddrFrom4([4]byte(raw))
	} else {
		a = netip.AddrFrom16([16]byte(raw))
	}
	return addrString(a), uint16(port), true
}

func readProc(k Kind) []Sock {
	var out []Sock
	type src struct{ file, proto string }
	var files []src
	if k.Listen || k.Established {
		files = append(files, src{"tcp", "tcp"}, src{"tcp6", "tcp"})
	}
	if k.UDP {
		files = append(files, src{"udp", "udp"}, src{"udp6", "udp"})
	}
	for _, f := range files {
		text, err := os.ReadFile("/proc/net/" + f.file)
		if err != nil {
			continue
		}
		lines := strings.Split(string(text), "\n")
		for _, line := range lines[1:] {
			fs := strings.Fields(line)
			if len(fs) < 10 {
				continue
			}
			local, lp, ok1 := parseProcAddr(fs[1])
			remote, rp, ok2 := parseProcAddr(fs[2])
			if !ok1 || !ok2 {
				continue
			}
			state, _ := strconv.ParseUint(fs[3], 16, 8)
			if f.proto == "tcp" && !(state == Established && k.Established) && !(state == Listen && k.Listen) {
				continue
			}
			uid, _ := strconv.ParseUint(fs[7], 10, 32)
			ino, _ := strconv.ParseUint(fs[9], 10, 64)
			out = append(out, Sock{f.proto, local, lp, remote, rp, uint8(state), uint32(uid), ino})
		}
	}
	return out
}

// TCPPeerOf devolve IP:porta do outro lado de uma conexão TCP estabelecida do processo
// (usado para achar o IP de origem de uma sessão SSH a partir do processo do sshd).
func TCPPeerOf(pid int) (string, bool) {
	inodes := map[uint64]bool{}
	for _, ino := range procfs.SocketInodes(pid) {
		inodes[ino] = true
	}
	if len(inodes) == 0 {
		return "", false
	}
	for _, s := range Read(Kind{Established: true}) {
		if s.State == Established && inodes[s.Inode] {
			return fmt.Sprintf("%s:%d", s.Remote, s.RemotePort), true
		}
	}
	return "", false
}
