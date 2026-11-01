package collectors

// Rede: portas novas em escuta e conexões de saída. Por ser por amostragem, conexões muito
// curtas podem escapar.

import (
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/DeathHapyness/loger/internal/config"
	"github.com/DeathHapyness/loger/internal/event"
	"github.com/DeathHapyness/loger/internal/ignore"
	"github.com/DeathHapyness/loger/internal/procfs"
	"github.com/DeathHapyness/loger/internal/sockets"
	"github.com/DeathHapyness/loger/internal/users"
	"github.com/DeathHapyness/loger/internal/util"
	"golang.org/x/sys/unix"
)

func init() {
	register("net", func(c *config.Config) bool { return c.Net.Enabled }, runNet)
}

var shells = []string{"sh", "bash", "dash", "zsh", "ksh", "fish", "ash", "csh", "tcsh"}

func ephemeralPorts() (uint16, uint16) {
	if s, ok := util.ReadText("/proc/sys/net/ipv4/ip_local_port_range", 64); ok {
		if f := strings.Fields(s); len(f) >= 2 {
			lo, err1 := strconv.ParseUint(f[0], 10, 16)
			hi, err2 := strconv.ParseUint(f[1], 10, 16)
			if err1 == nil && err2 == nil {
				return uint16(lo), uint16(hi)
			}
		}
	}
	return 32768, 60999
}

func isListener(s sockets.Sock, lo, hi uint16) bool {
	if s.Proto == "tcp" {
		return s.State == sockets.Listen
	}
	// UDP sem destino fora da faixa de portas efêmeras (usadas por clientes) é serviço.
	return s.RemotePort == 0 && s.LocalPort != 0 && (s.LocalPort < lo || s.LocalPort > hi)
}

func keyListen(s sockets.Sock) string {
	return fmt.Sprintf("%s/%s:%d", s.Proto, s.Local, s.LocalPort)
}

func keyConn(s sockets.Sock) string {
	return fmt.Sprintf("%s:%d>%s:%d", s.Local, s.LocalPort, s.Remote, s.RemotePort)
}

// socketOwners acha o pid dono de cada inode procurado (want: inode -> uid do socket).
// Primeiro olha só processos do mesmo uid do socket e do root, e para assim que achar
// todos; o que faltar (socket herdado por processo de outro usuário) sai numa varredura
// completa. Com newestFirst a busca começa pelos pids mais altos, onde costuma estar o
// dono de uma conexão que acabou de abrir; sem ele, um socket compartilhado (nginx,
// apache) fica com o processo principal, de pid menor.
func socketOwners(want map[uint64]uint32, newestFirst bool) map[uint64]int {
	found := make(map[uint64]int, len(want))
	uids := map[uint32]bool{0: true}
	for _, uid := range want {
		uids[uid] = true
	}
	pids := procfs.AllPIDs()
	slices.Sort(pids)
	if newestFirst {
		slices.Reverse(pids)
	}
	scan := func(filter bool) {
		for _, pid := range pids {
			if len(found) == len(want) {
				return
			}
			if filter {
				var st unix.Stat_t
				if unix.Stat("/proc/"+strconv.Itoa(pid), &st) != nil || !uids[st.Uid] {
					continue
				}
			}
			for _, ino := range procfs.SocketInodes(pid) {
				if _, ok := want[ino]; ok {
					if _, dup := found[ino]; !dup {
						found[ino] = pid
					}
				}
			}
		}
	}
	scan(true)
	if len(found) < len(want) {
		scan(false)
	}
	return found
}

func describeProc(p *procfs.Info, us *users.Users) (string, string, any) {
	if p == nil {
		return "processo desconhecido", "", nil
	}
	return fmt.Sprintf("%s (pid %d)", p.Exe, p.PID), us.Name(p.AUID), event.D{
		"pid": p.PID, "exe": p.Exe, "argv": p.Argv, "uid": p.UID, "auid": p.AUID, "ses": p.Ses,
	}
}

func listenSet(socks []sockets.Sock, lo, hi uint16) map[string]sockets.Sock {
	m := map[string]sockets.Sock{}
	for _, s := range socks {
		if isListener(s, lo, hi) {
			m[keyListen(s)] = s
		}
	}
	return m
}

func connSet(socks []sockets.Sock) map[string]sockets.Sock {
	m := map[string]sockets.Sock{}
	for _, s := range socks {
		if s.Proto == "tcp" && s.State == sockets.Established {
			m[keyConn(s)] = s
		}
	}
	return m
}

func runNet(ctx Ctx) {
	us := users.New()
	me := os.Getpid()
	lo, hi := ephemeralPorts()
	read := func(c config.NetCfg) []sockets.Sock {
		return sockets.Read(sockets.Kind{Listen: true, UDP: true, Established: c.Outbound})
	}
	var matcher *ignore.Matcher
	var matcherFor *config.Config

	// Estado inicial: não gera eventos, só registra o inventário de portas abertas.
	first := read(ctx.Cfg().Net)
	listeners, conns := listenSet(first, lo, hi), connSet(first)
	hadConns := ctx.Cfg().Net.Outbound
	inv := sortedMapKeys(listeners)
	ctx.Send(event.New("net.inventory", event.Notice, fmt.Sprintf("%d portas em escuta no início", len(inv))).
		WithData(event.D{"listening": inv}))

	for {
		cfg := ctx.Cfg()
		nc := cfg.Net
		time.Sleep(time.Duration(max(nc.IntervalMs, 200)) * time.Millisecond)
		if cfg != matcherFor {
			matcher, matcherFor = ignore.New(cfg.Exec), cfg
		}
		socks := read(nc)
		listenPorts := map[uint16]bool{}
		for _, s := range socks {
			if s.Proto == "tcp" && s.State == sockets.Listen {
				listenPorts[s.LocalPort] = true
			}
		}
		nowL, nowC := listenSet(socks, lo, hi), connSet(socks)

		var newL, newC []sockets.Sock
		for _, k := range sortedMapKeys(nowL) {
			if _, ok := listeners[k]; !ok {
				newL = append(newL, nowL[k])
			}
		}
		// Conexão de saída: a porta local não é uma porta em que a máquina escuta.
		for _, k := range sortedMapKeys(nowC) {
			s := nowC[k]
			if _, ok := conns[k]; !ok && !listenPorts[s.LocalPort] && s.Remote != "127.0.0.1" && s.Remote != "::1" {
				newC = append(newC, s)
			}
		}
		if !nc.Listen {
			newL = nil
		}
		// Sem a leitura anterior (outbound acabou de ser ligado por SIGHUP), toda conexão
		// aberta pareceria nova.
		if !nc.Outbound || !hadConns {
			newC = nil
		}
		hadConns = nc.Outbound

		if len(newL)+len(newC) > 0 {
			owners := map[uint64]int{}
			for i, group := range [][]sockets.Sock{newL, newC} {
				if len(group) == 0 {
					continue
				}
				want := map[uint64]uint32{}
				for _, s := range group {
					want[s.Inode] = s.UID
				}
				for ino, pid := range socketOwners(want, i == 1) {
					owners[ino] = pid
				}
			}
			info := func(s sockets.Sock) *procfs.Info {
				pid, ok := owners[s.Inode]
				if !ok {
					return nil
				}
				p, ok := procfs.Read(pid, 1024)
				if !ok {
					return nil
				}
				return &p
			}
			for _, s := range newL {
				p := info(s)
				if p != nil && p.PID == me {
					continue
				}
				who, user, data := describeProc(p, us)
				ctx.Send(event.New("net.listen", event.Warn, fmt.Sprintf("nova porta aberta %s %s:%d por %s", s.Proto, s.Local, s.LocalPort, who)).
					WithUser(user).WithData(event.D{"proto": s.Proto, "addr": s.Local, "port": s.LocalPort, "process": data}))
			}
			for _, s := range newC {
				p := info(s)
				if p == nil || p.PID == me || (nc.OnlySessions && p.AUID == procfs.NoID) {
					continue
				}
				who, user, data := describeProc(p, us)
				kind, level := "net.connect", event.Notice
				msg := fmt.Sprintf("conexão de saída para %s:%d por %s", s.Remote, s.RemotePort, who)
				if slices.Contains(shells, util.Basename(p.Exe)) {
					kind, level = "net.shell_socket", event.Alert
					msg = fmt.Sprintf("SHELL com conexão de rede para %s:%d (%s) — possível reverse shell", s.Remote, s.RemotePort, who)
				} else {
					parent, _ := procfs.Exe(p.PPID)
					if matcher.Match(ignore.Proc{Exe: p.Exe, User: user, Parent: parent, Argv: p.Argv}) {
						continue
					}
				}
				ctx.Send(event.New(kind, level, msg).WithUser(user).WithData(event.D{
					"local":  fmt.Sprintf("%s:%d", s.Local, s.LocalPort),
					"remote": s.Remote, "remote_port": s.RemotePort, "process": data,
				}))
			}
		}

		if nc.Listen {
			for _, k := range sortedMapKeys(listeners) {
				if _, ok := nowL[k]; !ok {
					ctx.Send(event.New("net.listen_closed", event.Notice, "porta fechada "+k).WithData(event.D{"socket": k}))
				}
			}
		}
		listeners, conns = nowL, nowC
	}
}
