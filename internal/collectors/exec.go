package collectors

// Processos e sessões.
//
// Fonte principal: o proc connector do kernel (netlink), que avisa a cada fork, exec, exit
// e troca de uid. Se não estiver disponível (container restrito), cai para varredura
// periódica de /proc.
//
// Sessões: o PAM grava loginuid/sessionid em cada login, e eles são herdados por todos os
// processos do usuário, mesmo depois de sudo/su. Assim cada comando fica ligado ao login.

import (
	"fmt"
	"os"
	"slices"
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
	register("exec", func(c *config.Config) bool { return c.Exec.Enabled }, runExec)
}

type proc struct {
	ppid  int
	uid   uint32
	euid  uint32
	auid  uint32
	ses   uint32
	start uint64
	exe   string
	argv  []string
}

type session struct {
	auid      uint32
	user      string
	startMs   int64
	firstSeen time.Time
	announced bool
	via       string
	from      string
	tty       string
	origin    string
	cmds      uint64
	leader    int
}

type tracker struct {
	ctx      Ctx
	users    *users.Users
	procs    map[int]*proc
	sessions map[uint32]*session
	lastGC   time.Time
	ign      *ignore.Matcher
	ignFor   *config.Config
}

func newTracker(ctx Ctx) *tracker {
	return &tracker{
		ctx:      ctx,
		users:    users.New(),
		procs:    map[int]*proc{},
		sessions: map[uint32]*session{},
		lastGC:   time.Now(),
	}
}

func validSession(auid, ses uint32) bool {
	return auid != procfs.NoID && ses != procfs.NoID
}

func fromInfo(p procfs.Info) *proc {
	return &proc{ppid: p.PPID, uid: p.UID, euid: p.EUID, auid: p.AUID, ses: p.Ses, start: p.Start, exe: p.Exe, argv: p.Argv}
}

// matcher reconstrói as regras de ignorar quando a configuração muda (SIGHUP).
func (t *tracker) matcher(cfg *config.Config) *ignore.Matcher {
	if cfg != t.ignFor {
		t.ign, t.ignFor = ignore.New(cfg.Exec), cfg
	}
	return t.ign
}

// scanExisting carrega os processos que já existem e anuncia as sessões ativas.
func (t *tracker) scanExisting() {
	cfg := t.ctx.Cfg()
	for _, pid := range procfs.AllPIDs() {
		auid, ses := procfs.LoginIDs(pid)
		var p procfs.Info
		var ok bool
		if validSession(auid, ses) || !cfg.Exec.OnlySessions {
			p, ok = procfs.Read(pid, cfg.Exec.MaxArgsLen)
		} else {
			p, ok = procfs.ReadLight(pid)
		}
		if !ok {
			continue
		}
		t.procs[pid] = fromInfo(p)
		if validSession(p.AUID, p.Ses) {
			t.touchSession(p, true)
		}
	}
	for _, id := range sortedKeys(t.sessions) {
		t.identify(id)
		t.announce(id, "session.active", "sessão já ativa quando o Loger iniciou")
	}
}

func sortedKeys(m map[uint32]*session) []uint32 {
	ids := make([]uint32, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

func (t *tracker) touchSession(p procfs.Info, quiet bool) {
	if _, ok := t.sessions[p.Ses]; ok {
		return
	}
	origin := ""
	if pp, ok := t.procs[p.PPID]; ok {
		origin = pp.exe
	}
	first := time.Now()
	if quiet {
		first = first.Add(-time.Minute)
	}
	t.sessions[p.Ses] = &session{
		auid:      p.AUID,
		user:      t.users.Name(p.AUID),
		startMs:   util.NowMs(),
		firstSeen: first,
		tty:       p.TTY,
		origin:    origin,
		leader:    p.PID,
	}
}

// identify descobre se a sessão é SSH e de qual IP, olhando os processos dela.
func (t *tracker) identify(ses uint32) {
	s, ok := t.sessions[ses]
	if !ok || s.from != "" {
		return
	}
	var pids []int
	for pid, p := range t.procs {
		if p.ses == ses {
			pids = append(pids, pid)
		}
	}
	slices.Sort(pids)
	for _, pid := range pids {
		if conn, ok := procfs.EnvVar(pid, "SSH_CONNECTION"); ok {
			if f := strings.Fields(conn); len(f) >= 2 {
				s.via = "ssh"
				s.from = f[0] + ":" + f[1]
				if s.tty == "" {
					tty, _ := procfs.EnvVar(pid, "SSH_TTY")
					s.tty = strings.TrimPrefix(tty, "/dev/")
				}
				return
			}
		}
	}
	// Sessões SSH sem shell (sftp interno, ssh -N com túnel) não têm processo com
	// SSH_CONNECTION: o IP sai do socket do próprio sshd.
	for _, pid := range pids {
		if strings.HasPrefix(util.Basename(t.procs[pid].exe), "sshd") {
			if peer, ok := sockets.TCPPeerOf(pid); ok {
				s.via = "ssh"
				s.from = peer
				return
			}
		}
	}
}

func (t *tracker) announce(ses uint32, kind, why string) {
	s, ok := t.sessions[ses]
	if !ok || s.announced {
		return
	}
	s.announced = true
	if s.via == "" {
		origin := util.Basename(s.origin)
		switch {
		case strings.HasPrefix(origin, "cron") || origin == "crond":
			s.via = "cron"
		case strings.HasPrefix(s.tty, "tty"):
			s.via = "console"
		default:
			s.via = "local"
		}
	}
	msg := fmt.Sprintf("%s: login %s %s", why, s.via, s.tty)
	if s.via == "ssh" {
		msg = fmt.Sprintf("%s: login SSH de %s %s", why, s.from, s.tty)
	}
	level := event.Notice
	if s.via == "cron" {
		level = event.Info
	}
	t.ctx.Send(event.New(kind, level, strings.TrimRight(msg, " ")).WithUser(s.user).WithData(event.D{
		"ses": ses, "auid": s.auid, "via": s.via, "from": s.from, "tty": s.tty, "origin": s.origin,
	}))
}

func (t *tracker) onFork(parent, child int) {
	var p proc
	if pp, ok := t.procs[parent]; ok {
		p = *pp
	} else if info, ok := procfs.ReadLight(child); ok {
		p = *fromInfo(info)
	} else {
		return
	}
	p.ppid = parent
	// O login (pam_loginuid) muda o loginuid sem gerar evento, então relê no fork.
	p.auid, p.ses = procfs.LoginIDs(child)
	t.procs[child] = &p
	if _, ok := t.sessions[p.ses]; validSession(p.auid, p.ses) && !ok {
		if info, ok := procfs.ReadLight(child); ok {
			t.touchSession(info, false)
		}
	}
}

func (t *tracker) onExec(pid int) {
	cfg := t.ctx.Cfg()
	auid, ses := procfs.LoginIDs(pid)
	known := t.procs[pid]
	if !validSession(auid, ses) && known != nil && validSession(known.auid, known.ses) {
		// O processo terminou antes da leitura: vale o que se sabia dele.
		auid, ses = known.auid, known.ses
	}
	inSession := validSession(auid, ses)

	// Fora de sessão o comando não vira evento: lê só o que precisa para continuar
	// acompanhando o processo (binário novo e ids), sem argumentos nem diretório.
	if cfg.Exec.OnlySessions && !inSession {
		if known != nil {
			if exe, _ := procfs.Exe(pid); exe != "" {
				known.exe = exe
			}
			known.argv = nil
			known.auid, known.ses = auid, ses
		} else if info, ok := procfs.ReadLight(pid); ok {
			t.procs[pid] = fromInfo(info)
		}
		return
	}

	p, ok := procfs.Read(pid, cfg.Exec.MaxArgsLen)
	gone := !ok
	if gone {
		if known == nil {
			return
		}
		p = procfs.Info{PID: pid, PPID: known.ppid, UID: known.uid, EUID: known.euid, AUID: known.auid, Ses: known.ses}
	}
	parentExe := ""
	if pp, ok := t.procs[p.PPID]; ok {
		parentExe = pp.exe
	}
	t.procs[pid] = fromInfo(p)

	inSession = validSession(p.AUID, p.Ses)
	if inSession {
		t.touchSession(p, false)
		s := t.sessions[p.Ses]
		s.cmds++
		if s.tty == "" {
			s.tty = p.TTY
		}
		if !s.announced {
			t.identify(p.Ses)
			if s.from != "" {
				t.announce(p.Ses, "session.start", "início de sessão")
			}
		}
	}
	if cfg.Exec.OnlySessions && !inSession {
		return
	}

	user := t.users.Name(p.UID)
	if inSession {
		user = t.users.Name(p.AUID)
	}
	if t.matcher(cfg).Match(ignore.Proc{Exe: p.Exe, User: user, Parent: parentExe, Argv: p.Argv}) {
		return
	}

	kind, level := classify(p)
	tags := []string{}
	if p.ExeDeleted {
		tags = append(tags, "binario_apagado")
		level = event.Alert
	}
	if gone {
		tags = append(tags, "terminou_antes_da_leitura")
	}
	cmd := util.JoinArgv(p.Argv)
	if len(p.Argv) == 0 {
		cmd = p.Comm
		if gone {
			cmd = "(processo curto demais: argumentos não capturados)"
		}
	}
	msg := cmd
	if inSession && p.EUID != p.AUID {
		msg = fmt.Sprintf("[como %s] %s", t.users.Name(p.EUID), cmd)
	}
	var sesVal any
	if inSession {
		sesVal = p.Ses
	}
	argv := p.Argv
	if argv == nil {
		argv = []string{}
	}
	t.ctx.Send(event.New(kind, level, msg).WithUser(user).WithData(event.D{
		"pid": p.PID, "ppid": p.PPID, "uid": p.UID, "euid": p.EUID, "auid": p.AUID, "ses": sesVal,
		"tty": p.TTY, "exe": p.Exe, "cwd": p.Cwd, "argv": argv, "parent": parentExe, "tags": tags,
	}))
}

func (t *tracker) onUID(pid int, ruid, euid uint32) {
	old, ok := t.procs[pid]
	if !ok {
		return
	}
	// Usuário comum (uid real != 0) virando root sem ser um binário setuid-root
	// (sudo, su, passwd...): sinal de exploit de escalada de privilégio.
	if euid == 0 && old.euid != 0 && old.uid != 0 && !setuidRoot(pid, old.exe) {
		who := old.uid
		if old.auid != procfs.NoID {
			who = old.auid
		}
		argv := old.argv
		if argv == nil {
			argv = procfs.Argv(pid, t.ctx.Cfg().Exec.MaxArgsLen)
		}
		t.ctx.Send(event.New("priv.escalation", event.Alert,
			fmt.Sprintf("processo %d (%s) virou root sem passar por sudo/su", pid, old.exe)).
			WithUser(t.users.Name(who)).
			WithData(event.D{"pid": pid, "exe": old.exe, "argv": argv, "old_uid": old.uid, "old_euid": old.euid, "ses": old.ses}))
	}
	old.uid, old.euid = ruid, euid
}

func (t *tracker) onPtrace(pid, tracer int) {
	if tracer == 0 {
		return
	}
	target, tr := t.procs[pid], t.procs[tracer]
	auid := procfs.NoID
	if tr != nil {
		auid = tr.auid
	}
	if t.ctx.Cfg().Exec.OnlySessions && auid == procfs.NoID {
		return
	}
	texe, trexe := "", ""
	if target != nil {
		texe = target.exe
	}
	if tr != nil {
		trexe = tr.exe
	}
	t.ctx.Send(event.New("proc.ptrace", event.Warn, fmt.Sprintf("%s (pid %d) se anexou ao processo %d (%s)", trexe, tracer, pid, texe)).
		WithUser(t.users.Name(auid)).
		WithData(event.D{"pid": pid, "exe": texe, "tracer_pid": tracer, "tracer_exe": trexe}))
}

func (t *tracker) onExit(pid int) {
	delete(t.procs, pid)
}

// housekeeping roda ~1x por segundo: anuncia sessões pendentes e encerra as que acabaram.
func (t *tracker) housekeeping() {
	for _, id := range sortedKeys(t.sessions) {
		if s := t.sessions[id]; !s.announced && time.Since(s.firstSeen) > 2*time.Second {
			t.identify(id)
			t.announce(id, "session.start", "início de sessão")
		}
	}

	// Se o kernel descartou eventos de exit, remove processos que já não existem.
	if time.Since(t.lastGC) > 30*time.Second {
		t.lastGC = time.Now()
		for pid, p := range t.procs {
			if s, ok := procfs.StartTime(pid); !ok || (s != p.start && p.start != 0) {
				delete(t.procs, pid)
			}
		}
	}

	alive := map[uint32]bool{}
	for _, p := range t.procs {
		alive[p.ses] = true
	}
	for _, id := range sortedKeys(t.sessions) {
		if alive[id] {
			continue
		}
		// Sessão que terminou antes de ser anunciada (ex: cron rápido) também é registrada.
		t.identify(id)
		s := t.sessions[id]
		delete(t.sessions, id)
		secs := (util.NowMs() - s.startMs) / 1000
		via := s.via
		if via == "" {
			via = "local"
		}
		from := ""
		if s.from != "" {
			from = " de " + s.from
		}
		level := event.Notice
		if via == "cron" {
			level = event.Info
		}
		t.ctx.Send(event.New("session.end", level,
			fmt.Sprintf("fim de sessão %s%s — duração %s, %d comandos", via, from, fmtDur(secs), s.cmds)).
			WithUser(s.user).
			WithData(event.D{"ses": id, "auid": s.auid, "via": via, "from": s.from, "tty": s.tty,
				"duration_secs": secs, "commands": s.cmds, "leader": s.leader}))
	}
}

// setuidRoot diz se o executável atual do processo é setuid root. No exec de um binário
// setuid o kernel avisa a troca de uid antes do próprio exec, então olha o exe atual em /proc.
// O stat em /proc/<pid>/exe segue o link do kernel e funciona até de dentro de um container,
// onde o caminho do binário do host não existe.
func setuidRoot(pid int, knownExe string) bool {
	var st unix.Stat_t
	if unix.Stat(fmt.Sprintf("/proc/%d/exe", pid), &st) != nil && unix.Stat(knownExe, &st) != nil {
		return false
	}
	return st.Uid == 0 && st.Mode&unix.S_ISUID != 0
}

func fmtDur(secs int64) string {
	switch {
	case secs < 60:
		return fmt.Sprintf("%ds", secs)
	case secs < 3600:
		return fmt.Sprintf("%dm%ds", secs/60, secs%60)
	}
	return fmt.Sprintf("%dh%dm", secs/3600, (secs%3600)/60)
}

// classify classifica o comando pelo nome do binário para facilitar filtros.
func classify(p procfs.Info) (string, string) {
	exe := p.Exe
	if exe == "" && len(p.Argv) > 0 {
		exe = p.Argv[0]
	}
	for _, dir := range []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/"} {
		if strings.HasPrefix(exe, dir) {
			return "exec.suspicious", event.Alert
		}
	}
	// Testa o nome real do binário e o nome usado para chamá-lo (nc -> nc.openbsd).
	if kind, level := classifyName(util.Basename(exe)); kind != "exec" {
		return kind, level
	}
	argv0 := ""
	if len(p.Argv) > 0 {
		argv0 = util.Basename(p.Argv[0])
	}
	return classifyName(argv0)
}

func classifyName(name string) (string, string) {
	switch name {
	case "sudo", "su", "pkexec", "doas", "runuser", "sudoedit":
		return "priv.cmd", event.Notice
	case "useradd", "userdel", "usermod", "adduser", "deluser", "passwd", "chpasswd", "chage",
		"groupadd", "groupdel", "groupmod", "gpasswd", "addgroup", "delgroup", "visudo", "vipw":
		return "account.cmd", event.Warn
	case "iptables", "ip6tables", "iptables-restore", "ip6tables-restore", "nft", "ufw", "firewall-cmd":
		return "firewall.cmd", event.Warn
	case "insmod", "rmmod", "modprobe":
		return "kernel.module_cmd", event.Warn
	case "crontab", "at", "batch":
		return "cron.cmd", event.Notice
	case "systemctl", "service", "rc-service", "update-rc.d", "chkconfig":
		return "service.cmd", event.Info
	case "mount", "umount":
		return "mount.cmd", event.Notice
	case "scp", "sftp-server", "rsync":
		return "ssh.transfer", event.Notice
	case "shutdown", "reboot", "halt", "poweroff", "init", "telinit":
		return "system.power_cmd", event.Warn
	case "nc", "ncat", "netcat", "socat", "nmap", "tcpdump":
		return "exec.net_tool", event.Warn
	case "history", "unset", "shred", "wipe":
		return "exec.antiforensics", event.Warn
	}
	return "exec", event.Info
}

func runExec(ctx Ctx) {
	t := newTracker(ctx)
	var conn int
	var err error
	if os.Getenv("LOGER_FORCE_POLL") != "" {
		err = fmt.Errorf("desativado por LOGER_FORCE_POLL")
	} else {
		conn, err = openConnector()
	}
	if err != nil {
		ctx.Send(event.New("loger.collector", event.Warn, fmt.Sprintf(
			"comandos: proc connector indisponível (%v), usando varredura de /proc — processos muito curtos podem escapar", err)))
		t.scanExisting()
		runPolling(t)
		return
	}
	ctx.Send(event.New("loger.collector", event.Info, "comandos: proc connector do kernel ativo (tempo real)"))
	t.scanExisting()
	runConnector(t, conn)
}
