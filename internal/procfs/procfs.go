package procfs

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/DeathHapyness/loger/internal/util"
)

const NoID = ^uint32(0)

type Info struct {
	PID        int
	PPID       int
	UID        uint32
	EUID       uint32
	AUID       uint32
	Ses        uint32
	Start      uint64
	Comm       string
	Exe        string
	ExeDeleted bool
	Cwd        string
	TTY        string
	Argv       []string
}

func dir(pid int) string {
	return "/proc/" + strconv.Itoa(pid)
}

// Read lê tudo de um processo. ok é falso se ele já terminou.
func Read(pid, maxArgs int) (Info, bool) {
	p, ok := ReadLight(pid)
	if !ok {
		return p, false
	}
	p.Cwd, _ = os.Readlink(dir(pid) + "/cwd")
	p.Argv = Argv(pid, maxArgs)
	return p, true
}

// ReadLight lê só o necessário para acompanhar o processo (ids, pai, binário, tty),
// sem argumentos nem diretório.
func ReadLight(pid int) (Info, bool) {
	p := Info{PID: pid}
	status, ok := util.ReadText(dir(pid)+"/status", 8192)
	if !ok {
		return p, false
	}
	for _, line := range strings.Split(status, "\n") {
		k, v, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		switch k {
		case "Name":
			p.Comm = strings.TrimSpace(v)
		case "PPid":
			p.PPID, _ = strconv.Atoi(strings.TrimSpace(v))
		case "Uid":
			f := strings.Fields(v)
			if len(f) >= 2 {
				p.UID = parseU32(f[0], 0)
				p.EUID = parseU32(f[1], 0)
			}
		}
	}
	p.AUID, p.Ses = LoginIDs(pid)
	if f, ok := statFields(pid); ok {
		if len(f) > 4 {
			nr, _ := strconv.ParseUint(f[4], 10, 64)
			p.TTY = ttyName(nr)
		}
		if len(f) > 19 {
			p.Start, _ = strconv.ParseUint(f[19], 10, 64)
		}
	}
	p.Exe, p.ExeDeleted = Exe(pid)
	return p, true
}

func Exe(pid int) (string, bool) {
	exe, err := os.Readlink(dir(pid) + "/exe")
	if err != nil {
		return "", false
	}
	if s, ok := strings.CutSuffix(exe, " (deleted)"); ok {
		return s, true
	}
	return exe, false
}

func parseU32(s string, def uint32) uint32 {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
	if err != nil {
		return def
	}
	return uint32(n)
}

// statFields devolve os campos de /proc/pid/stat depois do "(comm)".
func statFields(pid int) ([]string, bool) {
	stat, ok := util.ReadText(dir(pid)+"/stat", 4096)
	if !ok {
		return nil, false
	}
	i := strings.LastIndexByte(stat, ')')
	if i < 0 {
		return nil, false
	}
	return strings.Fields(stat[i+1:]), true
}

// StartTime é o instante de início do processo em ticks desde o boot. Junto com o pid,
// identifica o processo mesmo quando o pid é reutilizado.
func StartTime(pid int) (uint64, bool) {
	f, ok := statFields(pid)
	if !ok || len(f) <= 19 {
		return 0, false
	}
	n, err := strconv.ParseUint(f[19], 10, 64)
	return n, err == nil
}

func readBytes(path string, max int) ([]byte, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, int64(max)))
	return b, err == nil
}

func Argv(pid, max int) []string {
	raw, ok := readBytes(dir(pid)+"/cmdline", max)
	if !ok {
		return []string{}
	}
	parts := bytes.Split(raw, []byte{0})
	for len(parts) > 0 && len(parts[len(parts)-1]) == 0 {
		parts = parts[:len(parts)-1]
	}
	v := make([]string, len(parts), len(parts)+1)
	for i, p := range parts {
		v[i] = string(p)
	}
	if len(raw) >= max {
		v = append(v, "…(truncado)")
	}
	return v
}

// LoginIDs devolve loginuid e sessionid: definidos pelo PAM no login e herdados por tudo
// que o usuário roda, inclusive depois de sudo ou su.
func LoginIDs(pid int) (uint32, uint32) {
	rd := func(name string) uint32 {
		s, ok := util.ReadText(dir(pid)+"/"+name, 32)
		if !ok {
			return NoID
		}
		return parseU32(s, NoID)
	}
	return rd("loginuid"), rd("sessionid")
}

func EnvVar(pid int, name string) (string, bool) {
	raw, ok := readBytes(dir(pid)+"/environ", 256*1024)
	if !ok {
		return "", false
	}
	prefix := []byte(name + "=")
	for _, kv := range bytes.Split(raw, []byte{0}) {
		if v, found := bytes.CutPrefix(kv, prefix); found {
			return string(v), true
		}
	}
	return "", false
}

func ttyName(nr uint64) string {
	major := (nr >> 8) & 0xfff
	minor := (nr & 0xff) | ((nr >> 12) & 0xfff00)
	switch {
	case major == 0:
		return ""
	case major >= 136 && major <= 143:
		return fmt.Sprintf("pts/%d", (major-136)*256+minor)
	case major == 4 && minor < 64:
		return fmt.Sprintf("tty%d", minor)
	case major == 4:
		return fmt.Sprintf("ttyS%d", minor-64)
	}
	return fmt.Sprintf("tty(%d:%d)", major, minor)
}

// AllPIDs devolve todos os processos (não threads) existentes agora.
func AllPIDs() []int {
	f, err := os.Open("/proc")
	if err != nil {
		return nil
	}
	defer f.Close()
	names, _ := f.Readdirnames(-1)
	pids := make([]int, 0, len(names))
	for _, n := range names {
		if pid, err := strconv.Atoi(n); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids
}

// SocketInodes devolve os inodes dos sockets abertos por um processo.
func SocketInodes(pid int) []uint64 {
	fdDir := dir(pid) + "/fd"
	f, err := os.Open(fdDir)
	if err != nil {
		return nil
	}
	defer f.Close()
	names, _ := f.Readdirnames(-1)
	var out []uint64
	for _, n := range names {
		l, err := os.Readlink(fdDir + "/" + n)
		if err != nil {
			continue
		}
		if s, ok := strings.CutPrefix(l, "socket:["); ok {
			if ino, err := strconv.ParseUint(strings.TrimSuffix(s, "]"), 10, 64); err == nil {
				out = append(out, ino)
			}
		}
	}
	return out
}
