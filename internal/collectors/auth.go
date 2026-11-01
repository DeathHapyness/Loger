package collectors

// Autenticação: logins aceitos (com método e fingerprint da chave), falhas, usuários
// inválidos, força bruta e sudo/su negados.
//
// Fontes, na ordem: arquivo de log do syslog (auth.log/secure); se não houver, journalctl;
// se não houver, /var/log/btmp (registro binário de falhas, presente em todo Linux com sshd).

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/DeathHapyness/loger/internal/config"
	"github.com/DeathHapyness/loger/internal/event"
)

func init() {
	register("auth", func(c *config.Config) bool { return c.Auth.Enabled }, runAuth)
}

const bruteWindow = 60 * time.Second

type brute struct {
	start time.Time
	count int
	users []string
}

type authParser struct {
	ctx      Ctx
	perIP    map[string]*brute
	lastPurg time.Time
}

func newAuthParser(ctx Ctx) *authParser {
	return &authParser{ctx: ctx, perIP: map[string]*brute{}, lastPurg: time.Now()}
}

// after pega a palavra que vem depois de key: after("from 1.2.3.4 port", "from ") = "1.2.3.4".
func after(s, key string) string {
	i := strings.Index(s, key)
	if i < 0 {
		return ""
	}
	f := strings.Fields(s[i+len(key):])
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

func firstWord(s string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return f[0]
	}
	return ""
}

func (p *authParser) line(line string) {
	// Formato syslog: "... prog[pid]: mensagem"
	head, msg, ok := strings.Cut(line, "]: ")
	if !ok {
		if head, msg, ok = strings.Cut(line, ": "); !ok {
			return
		}
	}
	prog := head[strings.LastIndexByte(head, ' ')+1:]
	prog, _, _ = strings.Cut(prog, "[")
	switch {
	case strings.HasPrefix(prog, "sshd"):
		p.sshd(msg)
	case prog == "sudo":
		p.sudo(msg)
	case prog == "su":
		p.su(msg)
	}
}

func (p *authParser) sshd(msg string) {
	if rest, ok := strings.CutPrefix(msg, "Accepted "); ok {
		// Accepted publickey for joao from 1.2.3.4 port 5555 ssh2: ED25519 SHA256:abc
		method := firstWord(rest)
		user := after(rest, " for ")
		ip := after(rest, " from ")
		port := after(rest, " port ")
		key := ""
		if _, k, found := strings.Cut(rest, "ssh2: "); found {
			key = strings.TrimSpace(k)
		}
		m := fmt.Sprintf("login SSH aceito de %s:%s via %s", ip, port, method)
		if key != "" {
			m += fmt.Sprintf(" (chave %s)", key)
		}
		p.ctx.Send(event.New("ssh.auth_ok", event.Notice, m).WithUser(user).WithData(event.D{
			"method": method, "ip": ip, "port": port, "key": key,
		}))
	} else if rest, ok := strings.CutPrefix(msg, "Failed "); ok {
		// Failed password for [invalid user] joao from 1.2.3.4 port 5555 ssh2
		method := firstWord(rest)
		invalid := strings.Contains(rest, " for invalid user ")
		user := after(rest, " for ")
		if invalid {
			user = after(rest, "invalid user ")
		}
		ip := after(rest, " from ")
		port := after(rest, " port ")
		suffix := ""
		if invalid {
			suffix = " — usuário inexistente"
		}
		p.fail(ip, user, fmt.Sprintf("falha de login SSH (%s) de %s:%s%s", method, ip, port, suffix),
			event.D{"method": method, "ip": ip, "port": port, "invalid_user": invalid})
	} else if strings.HasPrefix(msg, "Invalid user ") {
		// Sempre vem um "Failed" depois; ignorado para não duplicar.
	} else if strings.Contains(msg, "maximum authentication attempts exceeded") {
		ip := after(msg, " from ")
		p.ctx.Send(event.New("ssh.auth_max", event.Warn, "máximo de tentativas excedido de "+ip).
			WithUser(after(msg, " for ")).WithData(event.D{"ip": ip}))
	}
}

func (p *authParser) fail(ip, user, msg string, data event.D) {
	now := time.Now()
	if now.Sub(p.lastPurg) > bruteWindow {
		for k, b := range p.perIP {
			if now.Sub(b.start) > bruteWindow {
				delete(p.perIP, k)
			}
		}
		p.lastPurg = now
	}
	b := p.perIP[ip]
	if b == nil || now.Sub(b.start) > bruteWindow {
		b = &brute{start: now, users: []string{}}
		p.perIP[ip] = b
	}
	b.count++
	if !slices.Contains(b.users, user) && len(b.users) < 20 {
		b.users = append(b.users, user)
	}
	// As primeiras falhas de cada IP são registradas uma a uma; depois vira um resumo.
	if b.count <= 3 {
		p.ctx.Send(event.New("ssh.auth_fail", event.Warn, msg).WithUser(user).WithData(data))
	}
	if b.count == max(p.ctx.Cfg().Auth.BruteforceThreshold, 2) {
		p.ctx.Send(event.New("ssh.bruteforce", event.Alert, fmt.Sprintf(
			"possível força bruta: %d falhas de %s em menos de 60s (usuários: %s)", b.count, ip, strings.Join(b.users, ", "))).
			WithData(event.D{"ip": ip, "failures": b.count, "users": slices.Clone(b.users)}))
	}
}

func (p *authParser) sudo(msg string) {
	// "joao : 3 incorrect password attempts ; TTY=pts/0 ; ... COMMAND=/bin/bash"
	// "joao : user NOT in sudoers ; TTY=..."
	user := strings.TrimSpace(strings.SplitN(msg, " : ", 2)[0])
	cmd := ""
	if parts := strings.Split(msg, "COMMAND="); len(parts) > 1 {
		cmd = strings.TrimSpace(parts[1])
	}
	switch {
	case strings.Contains(msg, "incorrect password attempt") || strings.Contains(msg, "NOT in sudoers") ||
		strings.Contains(msg, "command not allowed") || strings.Contains(msg, "a password is required"):
		reason := ""
		if parts := strings.Split(msg, " : "); len(parts) > 1 {
			reason = strings.TrimSpace(strings.Split(parts[1], " ; ")[0])
		}
		p.ctx.Send(event.New("priv.sudo_denied", event.Alert, fmt.Sprintf("sudo NEGADO (%s): %s", reason, cmd)).
			WithUser(user).WithData(event.D{"reason": reason, "command": cmd}))
	case strings.Contains(msg, "authentication failure") && strings.Contains(msg, "pam_unix(sudo"):
		u := after(msg, " ruser=")
		if u == "" {
			u = after(msg, " user=")
		}
		p.ctx.Send(event.New("priv.sudo_auth_fail", event.Warn, "senha errada no sudo").WithUser(u))
	}
}

func (p *authParser) su(msg string) {
	if strings.HasPrefix(msg, "FAILED SU") || (strings.Contains(msg, "authentication failure") && strings.Contains(msg, "pam_unix(su")) {
		u := after(msg, " ruser=")
		if u == "" {
			u = after(msg, "by ")
		}
		p.ctx.Send(event.New("priv.su_fail", event.Warn, "su falhou: "+strings.TrimSpace(msg)).WithUser(u))
	}
}

// tailFile segue um arquivo de texto como tail -F (aguenta rotação e truncamento),
// acordando pelo inotify em vez de ficar consultando o arquivo.
func tailFile(path string, p *authParser) {
	w := newFileWaiter(path)
	defer w.Close()
	var f *os.File
	var ino uint64
	var r *bufio.Reader
	var partial []byte
	var last []byte
	first := true
	for {
		if f == nil {
			if nf, err := os.Open(path); err == nil {
				f, ino = nf, inodeOf(nf)
				last = nil
				if first {
					end, _ := f.Seek(0, io.SeekEnd)
					last = make([]byte, min(end, tailCheck))
					f.ReadAt(last, end-int64(len(last)))
				}
				r = bufio.NewReaderSize(f, 64*1024)
				partial = nil
				w.rewatch()
			}
			first = false
		}
		got := false
		for f != nil {
			chunk, err := r.ReadBytes('\n')
			last = append(last, chunk...)
			if len(last) > tailCheck {
				last = append(last[:0], last[len(last)-tailCheck:]...)
			}
			if err != nil {
				partial = append(partial, chunk...)
				break
			}
			got = true
			line := append(partial, chunk...)
			partial = nil
			p.line(string(bytes.TrimRight(line, "\r\n")))
		}
		if got {
			continue
		}
		w.Wait(5 * time.Second)
		if f != nil && rewritten(f, r, path, ino, last) {
			f.Close()
			f = nil
		}
	}
}

const tailCheck = 64

// rewritten diz se o arquivo foi trocado, apagado ou truncado. Um truncamento seguido de
// escrita pode deixar o arquivo maior que a posição de leitura, então também confere se os
// últimos bytes lidos continuam no mesmo lugar.
func rewritten(f *os.File, r *bufio.Reader, path string, ino uint64, last []byte) bool {
	pos, _ := f.Seek(0, io.SeekCurrent)
	pos -= int64(r.Buffered())
	st, err := os.Stat(path)
	if err != nil || inodeStat(st) != ino || st.Size() < pos {
		return true
	}
	if len(last) == 0 || int64(len(last)) > pos {
		return false
	}
	b := make([]byte, len(last))
	if _, err := f.ReadAt(b, pos-int64(len(b))); err != nil {
		return true
	}
	return !bytes.Equal(b, last)
}

func runJournal(p *authParser) bool {
	cmd := exec.Command("journalctl", "-f", "-n", "0", "-o", "short",
		"_COMM=sshd", "_COMM=sshd-session", "_COMM=sudo", "_COMM=su")
	out, err := cmd.StdoutPipe()
	if err != nil {
		return false
	}
	if cmd.Start() != nil {
		return false
	}
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		p.line(sc.Text())
	}
	cmd.Wait()
	return true
}

// tailBtmp lê /var/log/btmp: registros binários de 384 bytes (struct utmp) com os logins
// que falharam.
func tailBtmp(path string, p *authParser) {
	const recSize = 384
	w := newFileWaiter(path)
	defer w.Close()
	var pos int64
	if st, err := os.Stat(path); err == nil {
		pos = st.Size()
	}
	str := func(b []byte) string { return string(bytes.TrimRight(b, "\x00")) }
	for {
		w.Wait(5 * time.Second)
		st, err := os.Stat(path)
		if err != nil {
			continue
		}
		if st.Size() < pos {
			pos = 0
			w.rewatch()
		}
		n := (st.Size() - pos) / recSize * recSize
		if n == 0 {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		buf := make([]byte, n)
		_, err = f.ReadAt(buf, pos)
		f.Close()
		if err != nil {
			continue
		}
		pos += n
		for rec := buf; len(rec) >= recSize; rec = rec[recSize:] {
			line, user, host := str(rec[8:40]), str(rec[44:76]), str(rec[76:332])
			p.fail(host, user, fmt.Sprintf("falha de login (%s) de %s", line, host), event.D{"ip": host, "line": line})
		}
	}
}

func runAuth(ctx Ctx) {
	p := newAuthParser(ctx)
	for _, path := range ctx.Cfg().Auth.Files {
		if _, err := os.Stat(path); err == nil {
			ctx.Send(event.New("loger.collector", event.Info, "autenticação: lendo "+path))
			tailFile(path, p)
		}
	}
	if _, err := os.Stat("/run/systemd/journal"); err == nil {
		ctx.Send(event.New("loger.collector", event.Info, "autenticação: lendo o journal do systemd"))
		if runJournal(p) {
			ctx.Send(event.New("loger.collector", event.Warn, "autenticação: journalctl terminou inesperadamente"))
		}
	}
	if _, err := os.Stat("/var/log/btmp"); err == nil {
		ctx.Send(event.New("loger.collector", event.Notice, "autenticação: só /var/log/btmp disponível (apenas falhas de login)"))
		tailBtmp("/var/log/btmp", p)
	}
	ctx.Send(event.New("loger.collector", event.Warn, "autenticação: nenhuma fonte encontrada (auth.log, journal ou btmp)"))
}
