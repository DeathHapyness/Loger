package remote

import (
	"crypto/cipher"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/DeathHapyness/loger/internal/config"
	"github.com/DeathHapyness/loger/internal/event"
	"github.com/DeathHapyness/loger/internal/store"
	"github.com/DeathHapyness/loger/internal/util"
)

// hostState tem lock próprio: hosts diferentes gravam em paralelo.
type hostState struct {
	mu       sync.Mutex
	file     *store.LogFile
	lastSeq  uint64
	hasSeq   bool
	lastHash string
	lastSeen time.Time
	silent   bool
}

type receiver struct {
	dir   string
	maxMB int64
	keep  int

	mu    sync.Mutex
	hosts map[string]*hostState

	ownMu sync.Mutex
	own   *store.Store
}

func (r *receiver) event(ev event.Ev) {
	fmt.Fprintf(os.Stderr, "[%s] %s %s\n", ev.Level, ev.Kind, ev.Msg)
	r.ownMu.Lock()
	defer r.ownMu.Unlock()
	if _, err := r.own.Append(ev); err != nil {
		fmt.Fprintln(os.Stderr, "loger: falha ao gravar:", err)
	}
}

func safeHost(h string) string {
	s := strings.Map(func(c rune) rune {
		if c < 0x80 && (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return c
		}
		return '_'
	}, h)
	s = strings.TrimLeft(s, ".")
	if s == "" {
		return "_"
	}
	return s
}

// host devolve o estado do host, abrindo o diretório dele na primeira vez.
func (r *receiver) host(name string) (*hostState, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if st, ok := r.hosts[name]; ok {
		return st, nil
	}
	hdir := filepath.Join(r.dir, name)
	f, err := store.OpenLogFile(hdir, r.maxMB, r.keep, true)
	if err != nil {
		return nil, err
	}
	st := &hostState{file: f, lastSeen: time.Now()}
	if last, ok := store.LastRecord(hdir); ok {
		st.lastSeq, st.hasSeq, st.lastHash = last.Seq, true, last.Hash
	}
	r.hosts[name] = st
	return st, nil
}

// loadKnown carrega os hosts que já mandaram logs antes. Assim um host que esteja fora
// quando o receptor reinicia também gera o alerta de silêncio.
func (r *receiver) loadKnown() int {
	entries, _ := os.ReadDir(r.dir)
	n := 0
	for _, e := range entries {
		if !e.IsDir() || e.Name() == "_receiver" || safeHost(e.Name()) != e.Name() {
			continue
		}
		if _, ok := store.LastRecord(filepath.Join(r.dir, e.Name())); !ok {
			continue
		}
		if _, err := r.host(e.Name()); err == nil {
			n++
		}
	}
	return n
}

func (r *receiver) snapshot() map[string]*hostState {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := make(map[string]*hostState, len(r.hosts))
	for k, v := range r.hosts {
		m[k] = v
	}
	return m
}

func (r *receiver) watchSilence(after time.Duration) {
	for range time.Tick(5 * time.Second) {
		hosts := r.snapshot()
		names := make([]string, 0, len(hosts))
		for h := range hosts {
			names = append(names, h)
		}
		sort.Strings(names)
		for _, h := range names {
			st := hosts[h]
			st.mu.Lock()
			st.file.Sync()
			var ev *event.Ev
			if !st.silent && time.Since(st.lastSeen) > after {
				st.silent = true
				e := event.New("remote.host_silent", event.Alert, fmt.Sprintf(
					"host %s parou de enviar sinal de vida há %ds (desligado, rede ou Loger morto?)", h, int(time.Since(st.lastSeen).Seconds()))).
					WithData(event.D{"host": h})
				ev = &e
			}
			st.mu.Unlock()
			if ev != nil {
				r.event(*ev)
			}
		}
	}
}

func Receive(cfg *config.Config) error {
	rc := cfg.Receiver
	c, err := ParseKey(rc.Key)
	if err != nil {
		return err
	}
	own, err := store.Open(filepath.Join(rc.Dir, "_receiver"), cfg.Log.MaxSizeMB, cfg.Log.Keep, cfg.Log.Harden, util.Hostname())
	if err != nil {
		return fmt.Errorf("%s: %v", rc.Dir, err)
	}
	l, err := net.Listen("tcp", rc.Listen)
	if err != nil {
		return fmt.Errorf("%s: %v", rc.Listen, err)
	}
	r := &receiver{dir: rc.Dir, maxMB: cfg.Log.MaxSizeMB, keep: cfg.Log.Keep, hosts: map[string]*hostState{}, own: own}
	known := r.loadKnown()
	r.event(event.New("receiver.start", event.Info, fmt.Sprintf("receptor ouvindo em %s (%d hosts conhecidos)", rc.Listen, known)))
	go r.watchSilence(time.Duration(max(rc.SilentAfterSecs, 10)) * time.Second)
	for {
		conn, err := l.Accept()
		if err != nil {
			continue
		}
		go r.handle(conn, c)
	}
}

func (r *receiver) handle(conn net.Conn, c cipher.AEAD) {
	defer conn.Close()
	peer := conn.RemoteAddr().String()
	bound := ""
	for {
		conn.SetReadDeadline(time.Now().Add(300 * time.Second))
		plain, err := readFrame(conn, c)
		if errors.Is(err, errAuth) || errors.Is(err, errBadFrame) {
			r.event(event.New("remote.auth_failed", event.Alert, fmt.Sprintf("conexão de %s rejeitada: %v", peer, err)).WithData(event.D{"peer": peer}))
			return
		}
		if err != nil {
			if bound != "" {
				r.event(event.New("remote.disconnected", event.Notice, fmt.Sprintf("host %s (%s) desconectou", bound, peer)).WithData(event.D{"host": bound}))
			}
			return
		}
		var head struct {
			Host      string `json:"host"`
			Heartbeat any    `json:"heartbeat"`
		}
		if json.Unmarshal(plain, &head) != nil {
			continue
		}
		host := safeHost(head.Host)
		if bound != "" && bound != host {
			r.event(event.New("remote.host_mismatch", event.Alert, fmt.Sprintf("conexão de %s mandou eventos como %s e depois como %s", peer, bound, host)))
			return
		}
		st, err := r.host(host)
		if err != nil {
			return
		}
		if bound == "" {
			bound = host
			r.event(event.New("remote.connected", event.Info, fmt.Sprintf("host %s conectado de %s", host, peer)).WithData(event.D{"host": host, "peer": peer}))
		}
		for _, ev := range r.store(st, host, plain, head.Heartbeat != nil) {
			r.event(ev.WithData(event.D{"host": host}))
		}
	}
}

// store confere a corrente do host e grava a linha original, assim "loger verify"
// funciona no diretório dele.
func (r *receiver) store(st *hostState, host string, plain []byte, heartbeat bool) []event.Ev {
	st.mu.Lock()
	defer st.mu.Unlock()
	var evs []event.Ev
	st.lastSeen = time.Now()
	if st.silent {
		st.silent = false
		evs = append(evs, event.New("remote.host_back", event.Notice, fmt.Sprintf("host %s voltou a enviar", host)))
	}
	if heartbeat {
		return evs
	}
	rec, err := event.Parse(plain)
	if err != nil {
		return evs
	}
	if rec.ComputeHash() != rec.Hash {
		evs = append(evs, event.New("remote.bad_record", event.Alert, fmt.Sprintf("%s: registro seq %d com hash inválido", host, rec.Seq)))
	} else if st.hasSeq {
		if rec.Seq <= st.lastSeq {
			evs = append(evs, event.New("remote.chain_reset", event.Alert, fmt.Sprintf(
				"%s: sequência voltou de %d para %d (log local apagado/reiniciado?)", host, st.lastSeq, rec.Seq)))
		} else if rec.Prev != st.lastHash {
			evs = append(evs, event.New("remote.chain_gap", event.Warn, fmt.Sprintf(
				"%s: faltam registros entre seq %d e %d (eventos perdidos durante queda do envio)", host, st.lastSeq, rec.Seq)))
		}
	}
	st.lastSeq, st.hasSeq, st.lastHash = rec.Seq, true, rec.Hash
	if err := st.file.Append(plain); err != nil {
		evs = append(evs, event.New("remote.write_error", event.Alert, fmt.Sprintf("%s: falha ao gravar: %v", host, err)))
	}
	return evs
}
