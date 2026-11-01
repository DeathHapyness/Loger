package ignore

import (
	"path"
	"strings"

	"github.com/DeathHapyness/loger/internal/config"
)

type Proc struct {
	Exe    string
	User   string
	Parent string
	Argv   []string
}

type Matcher struct {
	exact map[string]bool
	rules []config.IgnoreRule
}

func New(c config.ExecCfg) *Matcher {
	m := &Matcher{exact: map[string]bool{}, rules: c.Ignore}
	for _, e := range c.IgnoreExe {
		m.exact[e] = true
	}
	return m
}

func (m *Matcher) Match(p Proc) bool {
	if m.exact[p.Exe] {
		return true
	}
	if len(m.rules) == 0 {
		return false
	}
	argv := strings.Join(p.Argv, " ")
	for _, r := range m.rules {
		if fieldOK(r.Exe, p.Exe) && fieldOK(r.User, p.User) && fieldOK(r.Parent, p.Parent) &&
			(r.Argv == "" || wildcard(r.Argv, argv)) {
			return true
		}
	}
	return false
}

func fieldOK(pattern, value string) bool {
	if pattern == "" {
		return true
	}
	ok, _ := path.Match(pattern, value)
	return ok
}

// wildcard casa * (qualquer sequência, inclusive vazia) e ? (um caractere).
func wildcard(pattern, s string) bool {
	p, t := []rune(pattern), []rune(s)
	pi, ti := 0, 0
	star, mark := -1, 0
	for ti < len(t) {
		switch {
		case pi < len(p) && (p[pi] == '?' || p[pi] == t[ti]):
			pi++
			ti++
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, ti
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			ti = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}
