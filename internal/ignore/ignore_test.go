package ignore

import (
	"testing"

	"github.com/DeathHapyness/loger/internal/config"
)

func TestMatch(t *testing.T) {
	m := New(config.ExecCfg{
		IgnoreExe: []string{"/usr/bin/sleep"},
		Ignore: []config.IgnoreRule{
			{Exe: "/usr/lib/*/zabbix_agentd"},
			{User: "backup", Exe: "/usr/bin/rsync"},
			{Parent: "/usr/sbin/cron", Argv: "*--healthcheck*"},
		},
	})
	cases := []struct {
		p    Proc
		want bool
	}{
		{Proc{Exe: "/usr/bin/sleep"}, true},
		{Proc{Exe: "/usr/lib/zabbix/zabbix_agentd"}, true},
		{Proc{Exe: "/usr/lib/a/b/zabbix_agentd"}, false},
		{Proc{Exe: "/usr/bin/rsync", User: "backup"}, true},
		{Proc{Exe: "/usr/bin/rsync", User: "joao"}, false},
		{Proc{Exe: "/bin/sh", Parent: "/usr/sbin/cron", Argv: []string{"sh", "-c", "app --healthcheck now"}}, true},
		{Proc{Exe: "/bin/sh", Parent: "/usr/sbin/cron", Argv: []string{"sh", "-c", "app"}}, false},
		{Proc{Exe: "/bin/sh", Parent: "/bin/bash", Argv: []string{"app", "--healthcheck"}}, false},
	}
	for _, c := range cases {
		if got := m.Match(c.p); got != c.want {
			t.Errorf("%+v: %v", c.p, got)
		}
	}
}

func TestWildcard(t *testing.T) {
	cases := []struct {
		p, s string
		want bool
	}{
		{"*", "", true}, {"a*b", "a/x y/b", true}, {"a?c", "abc", true}, {"a?c", "ac", false},
		{"*x*", "abc", false}, {"ção*", "ção ü", true}, {"*a*a*a", "aaaa", true}, {"abc", "abcd", false},
	}
	for _, c := range cases {
		if got := wildcard(c.p, c.s); got != c.want {
			t.Errorf("%q ~ %q = %v", c.p, c.s, got)
		}
	}
}
