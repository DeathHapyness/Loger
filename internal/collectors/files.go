package collectors

// Arquivos sensíveis via inotify.
//
// Vigia diretórios (não arquivos soltos), para pegar editores que salvam com "grava
// temporário + rename" e arquivos que ainda não existem (ex: /etc/ld.so.preload). Além de
// "mudou", analisa o conteúdo de alguns arquivos: usuários criados/removidos, membros de
// grupos e chaves SSH adicionadas/removidas.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/DeathHapyness/loger/internal/config"
	"github.com/DeathHapyness/loger/internal/event"
	"github.com/DeathHapyness/loger/internal/users"
	"github.com/DeathHapyness/loger/internal/util"
	"golang.org/x/sys/unix"
)

func init() {
	register("files", func(c *config.Config) bool { return c.Files.Enabled }, runFiles)
}

const (
	maskDir = unix.IN_CLOSE_WRITE | unix.IN_ATTRIB | unix.IN_CREATE | unix.IN_DELETE |
		unix.IN_MOVED_FROM | unix.IN_MOVED_TO | unix.IN_DELETE_SELF | unix.IN_MOVE_SELF
	maskRead   = unix.IN_OPEN
	maxContent = 1024 * 1024
)

type watch struct {
	path string
	read bool
}

type pending struct {
	actions map[string]bool
	last    time.Time
}

// snap é o último estado conhecido de um arquivo: hash, metadados e, para os arquivos que
// são comparados linha a linha, o conteúdo.
type snap struct {
	hash    string
	mode    uint32
	uid     uint32
	gid     uint32
	content string
}

type watcher struct {
	ctx         Ctx
	fd          int
	wds         map[int]watch
	watchedDirs map[string]bool
	fileTargets map[string]bool
	dirTargets  []string
	readTargets map[string]bool
	snaps       map[string]snap
	pending     map[string]*pending
	reporting   bool
}

func snapshot(p string) (snap, bool) {
	st, err := os.Lstat(p)
	if err != nil || st.IsDir() {
		return snap{}, false
	}
	sys := st.Sys().(*syscall.Stat_t)
	s := snap{mode: sys.Mode & 0o7777, uid: sys.Uid, gid: sys.Gid}
	if st.Size() <= maxContent {
		if data, ok := util.ReadText(p, maxContent); ok {
			s.hash = util.Sha256Hex([]byte(data))
			if wantsContent(p) {
				s.content = data
			}
		}
	}
	return s, true
}

func wantsContent(p string) bool {
	return p == "/etc/passwd" || p == "/etc/group" || strings.HasPrefix(filepath.Base(p), "authorized_keys")
}

func levelFor(p string) string {
	n := filepath.Base(p)
	for _, prefix := range []string{"/etc/sudoers", "/etc/shadow", "/etc/passwd", "/etc/ld.so.preload",
		"/etc/pam.d", "/etc/systemd/system", "/etc/ssh/sshd_config"} {
		if strings.HasPrefix(p, prefix) {
			return event.Alert
		}
	}
	if strings.HasPrefix(n, "authorized_keys") || strings.Contains(p, "cron") {
		return event.Alert
	}
	return event.Warn
}

func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// within diz se p é dir ou está dentro dele.
func within(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, strings.TrimSuffix(dir, "/")+"/")
}

func (w *watcher) addWatch(path string, read bool) bool {
	if !read && w.watchedDirs[path] {
		return true
	}
	mask := uint32(maskDir | unix.IN_ONLYDIR)
	if read {
		mask = maskRead
	}
	wd, err := unix.InotifyAddWatch(w.fd, path, mask)
	if err != nil {
		return false
	}
	w.wds[wd] = watch{path, read}
	if !read {
		w.watchedDirs[path] = true
	}
	return true
}

// ensureDir vigia dir; se ele não existir, vigia o ancestral mais próximo que existe para
// ver a criação. Pastas criadas em sequência rápida (mkdir -p) podem surgir antes de a
// vigilância do pai começar, então depois de cada watch confere se o próximo nível já
// existe e continua descendo.
func (w *watcher) ensureDir(dir string) {
	dir = filepath.Clean(dir)
	for {
		d := dir
		for !(isDir(d) && w.addWatch(d, false)) {
			if d == "/" || d == "." {
				return
			}
			d = filepath.Dir(d)
		}
		if d == dir {
			return
		}
		rel, _ := filepath.Rel(d, dir)
		next := filepath.Join(d, strings.SplitN(rel, "/", 2)[0])
		if !isDir(next) {
			return
		}
	}
}

func (w *watcher) markCreated(p string) {
	if _, known := w.snaps[p]; known {
		return
	}
	if w.pending[p] == nil {
		w.pending[p] = &pending{actions: map[string]bool{}}
	}
	w.pending[p].actions["criado"] = true
	w.pending[p].last = time.Now()
}

// watchTree vigia dir e subpastas. Na carga inicial registra o estado dos arquivos; depois
// disso (reporting), arquivos encontrados numa pasta nova são reportados como criados.
func (w *watcher) watchTree(dir string, depth int) {
	w.ensureDir(dir)
	if depth == 0 || !isDir(dir) {
		return
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		switch {
		case e.IsDir():
			w.watchTree(p, depth-1)
		case w.reporting:
			w.markCreated(p)
		default:
			if s, ok := snapshot(p); ok {
				w.snaps[p] = s
			}
		}
	}
}

func (w *watcher) setup() {
	cfg := w.ctx.Cfg().Files
	for _, t := range cfg.Watch {
		p := filepath.Clean(t)
		name := filepath.Base(p)
		switch {
		case isDir(p):
			w.dirTargets = append(w.dirTargets, p)
			w.watchTree(p, 2)
		case strings.HasSuffix(t, "/") || strings.HasSuffix(name, ".d") || name == "cron" || name == "system":
			// Diretório que ainda não existe.
			w.dirTargets = append(w.dirTargets, p)
			w.ensureDir(p)
		default:
			w.fileTargets[p] = true
			if s, ok := snapshot(p); ok {
				w.snaps[p] = s
			}
			w.ensureDir(filepath.Dir(p))
		}
	}
	if cfg.AuthorizedKeys {
		w.setupKeys()
	}
	for _, t := range cfg.WatchReads {
		w.readTargets[t] = true
		w.addWatch(t, true)
	}
	w.reporting = true
}

func (w *watcher) setupKeys() {
	var homes []string
	for _, e := range users.Entries() {
		if (e.UID == 0 || e.UID >= 1000) && isDir(e.Home) && !strings.HasSuffix(e.Shell, "nologin") && !strings.HasSuffix(e.Shell, "false") {
			homes = append(homes, e.Home)
		}
	}
	homes = append(homes, "/root")
	slices.Sort(homes)
	for _, h := range slices.Compact(homes) {
		for _, name := range []string{"authorized_keys", "authorized_keys2"} {
			p := filepath.Join(h, ".ssh", name)
			if !w.fileTargets[p] {
				w.fileTargets[p] = true
				if s, ok := snapshot(p); ok {
					w.snaps[p] = s
				}
			}
		}
		w.ensureDir(filepath.Join(h, ".ssh"))
	}
}

func (w *watcher) relevant(p string) bool {
	if w.fileTargets[p] {
		return true
	}
	for _, d := range w.dirTargets {
		if within(p, d) {
			return true
		}
	}
	return false
}

func (w *watcher) handle(wd int, mask uint32, name string) {
	wt, ok := w.wds[wd]
	if !ok {
		return
	}
	if mask&unix.IN_IGNORED != 0 {
		delete(w.wds, wd)
		delete(w.watchedDirs, wt.path)
		// O diretório sumiu ou foi trocado: vigia de novo (ou o ancestral) para pegar a recriação.
		if !wt.read {
			w.ensureDir(wt.path)
		} else if w.readTargets[wt.path] {
			time.Sleep(50 * time.Millisecond)
			w.addWatch(wt.path, true)
		}
		return
	}
	if wt.read {
		if mask&unix.IN_OPEN != 0 {
			w.ctx.Send(event.New("file.read", event.Notice, wt.path+" foi aberto para leitura").WithData(event.D{"path": wt.path}))
		}
		return
	}
	path := wt.path
	if name != "" {
		path = filepath.Join(wt.path, name)
	}

	// Diretório novo: pode ser um alvo (ou caminho até um alvo) que ainda não existia.
	if mask&unix.IN_ISDIR != 0 && mask&(unix.IN_CREATE|unix.IN_MOVED_TO) != 0 {
		for _, d := range w.dirTargets {
			if within(path, d) {
				w.watchTree(path, 1)
				break
			}
		}
		for _, d := range w.dirTargets {
			if within(d, path) {
				w.ensureDir(d)
				if isDir(d) {
					w.watchTree(d, 2)
				}
			}
		}
		for f := range w.fileTargets {
			if within(filepath.Dir(f), path) {
				w.ensureDir(filepath.Dir(f))
			}
		}
		// Arquivos-alvo criados antes de a vigilância das pastas novas começar.
		for f := range w.fileTargets {
			if within(f, path) && exists(f) {
				w.markCreated(f)
			}
		}
	}
	if !w.relevant(path) {
		return
	}
	var action string
	switch {
	case mask&(unix.IN_CREATE|unix.IN_MOVED_TO) != 0:
		action = "criado"
	case mask&(unix.IN_DELETE|unix.IN_MOVED_FROM) != 0:
		action = "removido"
	case mask&unix.IN_CLOSE_WRITE != 0:
		action = "modificado"
	case mask&unix.IN_ATTRIB != 0:
		action = "permissões"
	default:
		return
	}
	p := w.pending[path]
	if p == nil {
		p = &pending{actions: map[string]bool{}}
		w.pending[path] = p
	}
	p.actions[action] = true
	p.last = time.Now()
}

// flush agrupa rajadas de eventos (um editor gera vários) e emite um evento por arquivo.
func (w *watcher) flush(force bool) {
	var ready []string
	for path, p := range w.pending {
		if force || time.Since(p.last) > 700*time.Millisecond {
			ready = append(ready, path)
		}
	}
	sort.Strings(ready)
	for _, path := range ready {
		pend := w.pending[path]
		delete(w.pending, path)
		old, hadOld := w.snaps[path]
		cur, hasCur := snapshot(path)
		if hadOld && hasCur && old == cur {
			continue // nada mudou de fato (ex: só abriram e fecharam)
		}
		if hasCur {
			w.snaps[path] = cur
		} else {
			delete(w.snaps, path)
		}
		var po, pn *snap
		if hadOld {
			po = &old
		}
		if hasCur {
			pn = &cur
		}
		w.report(path, pend.actions, po, pn)
		if path == "/etc/passwd" && w.ctx.Cfg().Files.AuthorizedKeys {
			w.setupKeys() // usuário novo: vigia o authorized_keys dele
		}
	}
}

func (w *watcher) report(path string, actions map[string]bool, old, cur *snap) {
	kind, verb := "file.modified", "modificado"
	switch {
	case old == nil && cur != nil:
		kind, verb = "file.created", "criado"
	case old != nil && cur == nil:
		kind, verb = "file.deleted", "removido"
	case old != nil && cur != nil && old.hash == cur.hash:
		kind, verb = "file.perm", "teve permissões/dono alterados"
	}
	var details []string
	if old != nil && cur != nil {
		if old.mode != cur.mode {
			details = append(details, fmt.Sprintf("modo %o -> %o", old.mode, cur.mode))
		}
		if old.uid != cur.uid || old.gid != cur.gid {
			details = append(details, fmt.Sprintf("dono %d:%d -> %d:%d", old.uid, old.gid, cur.uid, cur.gid))
		}
	}
	msg := path + " " + verb
	if len(details) > 0 {
		msg += " (" + strings.Join(details, ", ") + ")"
	}
	acts := make([]string, 0, len(actions))
	for a := range actions {
		acts = append(acts, a)
	}
	sort.Strings(acts)
	data := event.D{"path": path, "actions": acts, "old_sha256": nil, "new_sha256": nil, "mode": nil, "uid": nil, "gid": nil}
	if old != nil {
		data["old_sha256"] = old.hash
	}
	if cur != nil {
		data["new_sha256"] = cur.hash
		data["mode"] = fmt.Sprintf("%o", cur.mode)
		data["uid"] = cur.uid
		data["gid"] = cur.gid
	}
	w.ctx.Send(event.New(kind, levelFor(path), msg).WithData(data))

	var oc, nc string
	if old != nil {
		oc = old.content
	}
	if cur != nil {
		nc = cur.content
	}
	switch {
	case path == "/etc/passwd":
		w.diffAccounts(oc, nc)
	case path == "/etc/group":
		w.diffGroups(oc, nc)
	case strings.HasPrefix(filepath.Base(path), "authorized_keys"):
		w.diffKeys(path, oc, nc)
	}
}

func lines(text string) []string {
	return strings.FieldsFunc(text, func(r rune) bool { return r == '\n' })
}

func sortedMapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (w *watcher) diffAccounts(oldText, newText string) {
	parse := func(t string) map[string]string {
		m := map[string]string{}
		for _, l := range lines(t) {
			name, _, _ := strings.Cut(l, ":")
			m[name] = strings.TrimSuffix(l, "\r")
		}
		return m
	}
	o, n := parse(oldText), parse(newText)
	field := func(f []string, i int) string {
		if i < len(f) {
			return f[i]
		}
		return "?"
	}
	for _, name := range sortedMapKeys(n) {
		line := n[name]
		f := strings.Split(line, ":")
		oldLine, had := o[name]
		switch {
		case !had:
			w.ctx.Send(event.New("account.user_added", event.Alert,
				fmt.Sprintf("usuário criado: %s (uid %s, shell %s)", name, field(f, 2), field(f, 6))).
				WithUser(name).WithData(event.D{"entry": line}))
		case oldLine != line:
			of := strings.Split(oldLine, ":")
			level := event.Warn
			if field(f, 2) == "0" && field(of, 2) != "0" {
				level = event.Alert
			}
			w.ctx.Send(event.New("account.user_changed", level, fmt.Sprintf("usuário alterado: %s: %s -> %s", name, oldLine, line)).
				WithUser(name).WithData(event.D{"old": oldLine, "new": line}))
		}
	}
	for _, name := range sortedMapKeys(o) {
		if _, ok := n[name]; !ok {
			w.ctx.Send(event.New("account.user_removed", event.Warn, "usuário removido: "+name).WithUser(name))
		}
	}
}

var privGroups = []string{"root", "sudo", "wheel", "admin", "adm", "docker", "lxd", "disk", "shadow"}

func (w *watcher) diffGroups(oldText, newText string) {
	parse := func(t string) map[string][]string {
		m := map[string][]string{}
		for _, l := range lines(t) {
			f := strings.Split(strings.TrimSuffix(l, "\r"), ":")
			if len(f) < 4 {
				continue
			}
			var members []string
			for _, s := range strings.Split(f[3], ",") {
				if s != "" {
					members = append(members, s)
				}
			}
			slices.Sort(members)
			m[f[0]] = slices.Compact(members)
		}
		return m
	}
	o, n := parse(oldText), parse(newText)
	for _, g := range sortedMapKeys(n) {
		before, had := o[g]
		if !had {
			w.ctx.Send(event.New("account.group_added", event.Notice, "grupo criado: "+g))
		}
		for _, m := range n[g] {
			if !slices.Contains(before, m) {
				level := event.Notice
				if slices.Contains(privGroups, g) {
					level = event.Alert
				}
				w.ctx.Send(event.New("account.group_member_added", level, fmt.Sprintf("%s adicionado ao grupo %s", m, g)).
					WithUser(m).WithData(event.D{"group": g}))
			}
		}
		for _, m := range before {
			if !slices.Contains(n[g], m) {
				w.ctx.Send(event.New("account.group_member_removed", event.Notice, fmt.Sprintf("%s removido do grupo %s", m, g)).
					WithUser(m).WithData(event.D{"group": g}))
			}
		}
	}
	for _, g := range sortedMapKeys(o) {
		if _, ok := n[g]; !ok {
			w.ctx.Send(event.New("account.group_removed", event.Notice, "grupo removido: "+g))
		}
	}
}

func describeKey(line string) (ktype, fp, comment string) {
	// [opções] tipo base64 [comentário]
	parts := strings.Fields(line)
	i := slices.IndexFunc(parts, func(p string) bool {
		return strings.HasPrefix(p, "ssh-") || strings.HasPrefix(p, "ecdsa-") || strings.HasPrefix(p, "sk-")
	})
	if i < 0 {
		i = 0
	}
	ktype = "?"
	if i < len(parts) {
		ktype = parts[i]
	}
	if i+1 < len(parts) {
		fp, _ = util.SSHFingerprint(parts[i+1])
	}
	if i+2 < len(parts) {
		comment = strings.Join(parts[i+2:], " ")
	}
	return
}

func (w *watcher) diffKeys(path, oldText, newText string) {
	keys := func(t string) map[string]bool {
		m := map[string]bool{}
		for _, l := range lines(t) {
			if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
				m[l] = true
			}
		}
		return m
	}
	o, n := keys(oldText), keys(newText)
	owner := filepath.Base(filepath.Dir(filepath.Dir(path)))
	send := func(kind, level, verb, k string) {
		t, fp, c := describeKey(k)
		w.ctx.Send(event.New(kind, level, fmt.Sprintf("%s %s: %s %s %s", verb, path, t, fp, c)).
			WithUser(owner).WithData(event.D{"path": path, "type": t, "fingerprint": fp, "comment": c}))
	}
	for _, k := range sortedMapKeys(n) {
		if !o[k] {
			send("ssh.key_added", event.Alert, "chave SSH ADICIONADA em", k)
		}
	}
	for _, k := range sortedMapKeys(o) {
		if !n[k] {
			send("ssh.key_removed", event.Warn, "chave SSH removida de", k)
		}
	}
}

// parseInotify percorre um buffer de struct inotify_event { int wd; u32 mask; u32 cookie;
// u32 len; char name[len]; }.
func parseInotify(buf []byte, fn func(wd int, mask uint32, name string)) {
	for off := 0; off+unix.SizeofInotifyEvent <= len(buf); {
		wd := int(int32(binary.NativeEndian.Uint32(buf[off:])))
		mask := binary.NativeEndian.Uint32(buf[off+4:])
		l := int(binary.NativeEndian.Uint32(buf[off+12:]))
		start := off + unix.SizeofInotifyEvent
		end := min(start+l, len(buf))
		name := buf[start:end]
		if i := bytes.IndexByte(name, 0); i >= 0 {
			name = name[:i]
		}
		fn(wd, mask, string(name))
		off = start + l
	}
}

func runFiles(ctx Ctx) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC)
	if err != nil {
		ctx.Send(event.New("loger.collector", event.Warn, fmt.Sprintf("arquivos: inotify indisponível (%v)", err)))
		return
	}
	w := &watcher{
		ctx:         ctx,
		fd:          fd,
		wds:         map[int]watch{},
		watchedDirs: map[string]bool{},
		fileTargets: map[string]bool{},
		readTargets: map[string]bool{},
		snaps:       map[string]snap{},
		pending:     map[string]*pending{},
	}
	w.setup()
	ctx.Send(event.New("loger.collector", event.Info, fmt.Sprintf("arquivos: vigiando %d diretórios", len(w.watchedDirs))))

	buf := make([]byte, 64*1024)
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for {
		timeout := 5000
		if len(w.pending) > 0 {
			timeout = 300
		}
		if n, err := unix.Poll(fds, timeout); err == nil && n > 0 {
			if n, err := unix.Read(fd, buf); err == nil && n > 0 {
				parseInotify(buf[:n], func(wd int, mask uint32, name string) {
					if mask&unix.IN_Q_OVERFLOW != 0 {
						ctx.Send(event.New("loger.events_lost", event.Warn, "inotify: fila estourou, eventos de arquivo perdidos"))
						return
					}
					w.handle(wd, mask, name)
				})
			}
		}
		w.flush(false)
	}
}
