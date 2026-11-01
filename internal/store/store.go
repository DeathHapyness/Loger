package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/DeathHapyness/loger/internal/event"
	"github.com/DeathHapyness/loger/internal/util"
	"golang.org/x/sys/unix"
)

const Base = "loger.log"

const fsAppendFL = 0x20

// LogFile é um arquivo com rotação, usado tanto pelo daemon quanto pelo receptor remoto.
type LogFile struct {
	dir    string
	file   *os.File
	ino    uint64
	size   int64
	max    int64
	keep   int
	harden bool
	dirty  bool
}

func OpenLogFile(dir string, maxSizeMB int64, keep int, harden bool) (*LogFile, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	_ = os.Chmod(dir, 0o700)
	l := &LogFile{dir: dir, max: max(maxSizeMB, 1) * 1024 * 1024, keep: max(keep, 1), harden: harden}
	if err := l.openCurrent(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *LogFile) path(i int) string {
	if i == 0 {
		return filepath.Join(l.dir, Base)
	}
	return filepath.Join(l.dir, Base+"."+strconv.Itoa(i))
}

func (l *LogFile) openCurrent() error {
	p := l.path(0)
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	if l.harden {
		SetAppendOnly(p, true)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	if l.file != nil {
		l.file.Close()
	}
	l.file = f
	l.ino = st.Sys().(*syscall.Stat_t).Ino
	l.size = st.Size()
	return nil
}

func (l *LogFile) Append(line []byte) error {
	if l.size > 0 && l.size+int64(len(line))+1 > l.max {
		if err := l.rotate(); err != nil {
			return err
		}
	}
	buf := make([]byte, 0, len(line)+1)
	buf = append(append(buf, line...), '\n')
	n, err := l.file.Write(buf)
	l.size += int64(n)
	l.dirty = true
	return err
}

func (l *LogFile) rotate() error {
	oldest := l.path(l.keep)
	if exists(oldest) {
		SetAppendOnly(oldest, false)
		if err := os.Remove(oldest); err != nil {
			return err
		}
	}
	for i := l.keep - 1; i >= 0; i-- {
		from := l.path(i)
		if !exists(from) {
			continue
		}
		SetAppendOnly(from, false)
		if err := os.Rename(from, l.path(i+1)); err != nil {
			return err
		}
		if l.harden {
			SetAppendOnly(l.path(i+1), true)
		}
	}
	return l.openCurrent()
}

// Sync faz fsync só se algo foi gravado desde a última chamada.
func (l *LogFile) Sync() {
	if l.dirty {
		_ = l.file.Sync()
		l.dirty = false
	}
}

func (l *LogFile) Close() error {
	l.Sync()
	return l.file.Close()
}

// CheckTamper verifica se alguém apagou, trocou ou truncou o arquivo atual.
// Se sim, reabre um arquivo novo e devolve a descrição do problema.
func (l *LogFile) CheckTamper() string {
	p := l.path(0)
	var problem string
	st, err := os.Stat(p)
	switch {
	case err != nil:
		problem = fmt.Sprintf("%s foi apagado", p)
	case st.Sys().(*syscall.Stat_t).Ino != l.ino:
		problem = fmt.Sprintf("%s foi substituído por outro arquivo", p)
	case st.Size() < l.size:
		problem = fmt.Sprintf("%s foi truncado (%d -> %d bytes)", p, l.size, st.Size())
	}
	if problem != "" {
		_ = l.openCurrent()
	}
	return problem
}

// Store é um LogFile com a corrente de hashes.
type Store struct {
	Log      *LogFile
	host     string
	seq      uint64
	lastHash string
	LastKind string
	LastTs   string
}

func Open(dir string, maxSizeMB int64, keep int, harden bool, host string) (*Store, error) {
	l, err := OpenLogFile(dir, maxSizeMB, keep, harden)
	if err != nil {
		return nil, err
	}
	s := &Store{Log: l, host: host, lastHash: event.Genesis}
	if r, ok := LastRecord(dir); ok {
		s.seq = r.Seq + 1
		s.lastHash = r.Hash
		s.LastKind = r.Kind
		s.LastTs = r.Ts
	}
	return s, nil
}

func (s *Store) Append(ev event.Ev) ([]byte, error) {
	r := event.FromEv(ev, s.seq, s.host, s.lastHash)
	line := r.Line()
	if err := s.Log.Append(line); err != nil {
		return nil, err
	}
	s.seq++
	s.lastHash = r.Hash
	return line, nil
}

// Tick roda a cada segundo: fsync e verificação de adulteração.
func (s *Store) Tick() (event.Ev, bool) {
	s.Log.Sync()
	if p := s.Log.CheckTamper(); p != "" {
		return event.New("loger.log_tampered", event.Alert, "arquivo de log adulterado: "+p), true
	}
	return event.Ev{}, false
}

// LastRecord olha o arquivo atual e, se vazio, o .1.
func LastRecord(dir string) (event.Record, bool) {
	for _, name := range []string{Base, Base + ".1"} {
		if line, ok := util.LastLine(filepath.Join(dir, name)); ok {
			if r, err := event.Parse(line); err == nil {
				return r, true
			}
		}
	}
	return event.Record{}, false
}

// LogFiles devolve os arquivos de log do diretório, do mais antigo para o mais novo.
func LogFiles(dir string) []string {
	entries, _ := os.ReadDir(dir)
	type numbered struct {
		n    int
		path string
	}
	var v []numbered
	for _, e := range entries {
		name := e.Name()
		n := 0
		if name != Base {
			rest, ok := strings.CutPrefix(name, Base+".")
			if !ok {
				continue
			}
			var err error
			if n, err = strconv.Atoi(rest); err != nil {
				continue
			}
		}
		v = append(v, numbered{n, filepath.Join(dir, name)})
	}
	sort.Slice(v, func(i, j int) bool { return v[i].n > v[j].n })
	out := make([]string, len(v))
	for i, x := range v {
		out[i] = x.path
	}
	return out
}

func NoLogs(dir string) error {
	return fmt.Errorf("nenhum log em %s", dir)
}

// SetAppendOnly faz chattr +a / -a. Silencioso se o sistema de arquivos não suportar.
func SetAppendOnly(path string, on bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	fd := int(f.Fd())
	flags, err := unix.IoctlGetInt(fd, unix.FS_IOC_GETFLAGS)
	if err != nil {
		return
	}
	nf := flags &^ fsAppendFL
	if on {
		nf = flags | fsAppendFL
	}
	if nf != flags {
		_ = unix.IoctlSetPointerInt(fd, unix.FS_IOC_SETFLAGS, nf)
	}
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return !errors.Is(err, os.ErrNotExist)
}
