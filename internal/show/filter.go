package show

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/DeathHapyness/loger/internal/event"
	"github.com/DeathHapyness/loger/internal/util"
)

type Filter struct {
	Kinds    []string
	User     string
	HasUser  bool
	Since    int64
	Until    int64
	MinLevel int
	Grep     string
	Ses      uint64
	HasSes   bool
	Last     int
	Follow   bool
	JSON     bool

	kindNeedles [][]byte
	userNeedle  []byte
	grepNeedle  []byte
	levelOK     [][]byte
}

func Parse(args []string) (*Filter, error) {
	f := &Filter{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		val := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s precisa de um valor", a)
			}
			i++
			return args[i], nil
		}
		var v string
		var err error
		switch a {
		case "-f", "--follow":
			f.Follow = true
			continue
		case "--json":
			f.JSON = true
			continue
		}
		if v, err = val(); err != nil {
			return nil, err
		}
		switch a {
		case "-k", "--kind":
			f.Kinds = append(f.Kinds, strings.Split(v, ",")...)
		case "-u", "--user":
			f.User, f.HasUser = v, true
		case "-s", "--since":
			ms, ok := util.ParseWhen(v)
			if !ok {
				return nil, fmt.Errorf("data inválida em --since")
			}
			f.Since = ms
		case "--until":
			ms, ok := util.ParseWhen(v)
			if !ok {
				return nil, fmt.Errorf("data inválida em --until")
			}
			f.Until = ms
		case "-l", "--level":
			f.MinLevel = event.LevelRank(v)
		case "-g", "--grep":
			f.Grep = strings.ToLower(v)
		case "--ses":
			if f.Ses, err = strconv.ParseUint(v, 10, 64); err != nil {
				return nil, fmt.Errorf("--ses precisa de um número")
			}
			f.HasSes = true
		case "-n":
			if f.Last, err = strconv.Atoi(v); err != nil || f.Last < 0 {
				return nil, fmt.Errorf("-n precisa de um número")
			}
		case "-d", "--dir", "-c", "--config":
		default:
			return nil, fmt.Errorf("opção desconhecida: %s", a)
		}
	}
	f.prepare()
	return f, nil
}

// prepare monta os trechos de texto que uma linha precisa conter para poder casar com o
// filtro. Testar isso nos bytes crus evita o parse do JSON da maioria das linhas.
func (f *Filter) prepare() {
	for _, k := range f.Kinds {
		f.kindNeedles = append(f.kindNeedles, []byte(`"kind":"`+k))
	}
	if f.HasUser {
		f.userNeedle = []byte(`"user":"` + f.User + `"`)
		if f.User == "" || strings.ContainsAny(f.User, "\"\\") || hasControl(f.User) {
			f.userNeedle = nil
		}
	}
	if f.Grep != "" && !strings.ContainsAny(f.Grep, "\"\\") && !hasControl(f.Grep) {
		f.grepNeedle = []byte(f.Grep)
	}
	if f.MinLevel > 0 {
		for _, l := range []string{event.Info, event.Notice, event.Warn, event.Alert} {
			if event.LevelRank(l) >= f.MinLevel {
				f.levelOK = append(f.levelOK, []byte(`"level":"`+l+`"`))
			}
		}
	}
}

func hasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 {
			return true
		}
	}
	return false
}

func containsAny(line []byte, needles [][]byte) bool {
	for _, n := range needles {
		if bytes.Contains(line, n) {
			return true
		}
	}
	return false
}

// quick descarta linhas que com certeza não casam, sem fazer parse.
func (f *Filter) quick(line []byte) bool {
	if len(f.kindNeedles) > 0 && !containsAny(line, f.kindNeedles) {
		return false
	}
	if f.userNeedle != nil && !bytes.Contains(line, f.userNeedle) {
		return false
	}
	if len(f.levelOK) > 0 && !containsAny(line, f.levelOK) {
		return false
	}
	if f.HasSes && !bytes.Contains(line, []byte(`"ses":`+strconv.FormatUint(f.Ses, 10))) {
		return false
	}
	if f.grepNeedle != nil && !bytes.Contains(bytes.ToLower(line), f.grepNeedle) {
		return false
	}
	return true
}

func (f *Filter) Matches(r *event.Record) bool {
	if len(f.Kinds) > 0 {
		ok := false
		for _, k := range f.Kinds {
			if r.Kind == k || strings.HasPrefix(r.Kind, k+".") {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if f.HasUser && r.User != f.User {
		return false
	}
	if event.LevelRank(r.Level) < f.MinLevel {
		return false
	}
	if f.Since > 0 || f.Until > 0 {
		t := r.TsMs()
		if (f.Since > 0 && t < f.Since) || (f.Until > 0 && t > f.Until) {
			return false
		}
	}
	if f.HasSes {
		if s, ok := r.Ses(); !ok || s != f.Ses {
			return false
		}
	}
	if f.Grep != "" {
		if !strings.Contains(strings.ToLower(r.Msg), f.Grep) && !bytes.Contains(bytes.ToLower(r.Data), []byte(f.Grep)) {
			return false
		}
	}
	return true
}

// Match junta o filtro rápido e o completo; devolve o registro se a linha casar.
func (f *Filter) Match(line []byte) (event.Record, bool) {
	if !f.quick(line) {
		return event.Record{}, false
	}
	r, err := event.Parse(line)
	if err != nil || !f.Matches(&r) {
		return event.Record{}, false
	}
	return r, true
}
