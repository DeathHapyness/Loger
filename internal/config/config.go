package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

const DefaultPath = "/etc/loger/loger.toml"

type Config struct {
	Log      LogCfg      `toml:"log"`
	Exec     ExecCfg     `toml:"exec"`
	Auth     AuthCfg     `toml:"auth"`
	Files    FilesCfg    `toml:"files"`
	Net      NetCfg      `toml:"net"`
	System   SystemCfg   `toml:"system"`
	Remote   RemoteCfg   `toml:"remote"`
	Receiver ReceiverCfg `toml:"receiver"`
}

type LogCfg struct {
	Dir       string `toml:"dir"`
	MaxSizeMB int64  `toml:"max_size_mb"`
	Keep      int    `toml:"keep"`
	Harden    bool   `toml:"harden"`
}

type ExecCfg struct {
	Enabled        bool         `toml:"enabled"`
	OnlySessions   bool         `toml:"only_sessions"`
	IgnoreExe      []string     `toml:"ignore_exe"`
	Ignore         []IgnoreRule `toml:"ignore"`
	MaxArgsLen     int          `toml:"max_args_len"`
	PollIntervalMs int          `toml:"poll_interval_ms"`
}

// IgnoreRule descarta comandos (e as conexões de rede deles). Todos os campos preenchidos
// precisam casar; basta uma regra casar para o evento ser ignorado.
type IgnoreRule struct {
	Exe    string `toml:"exe"`
	User   string `toml:"user"`
	Parent string `toml:"parent"`
	Argv   string `toml:"argv"`
}

type AuthCfg struct {
	Enabled             bool     `toml:"enabled"`
	Files               []string `toml:"files"`
	BruteforceThreshold int      `toml:"bruteforce_threshold"`
}

type FilesCfg struct {
	Enabled        bool     `toml:"enabled"`
	Watch          []string `toml:"watch"`
	WatchReads     []string `toml:"watch_reads"`
	AuthorizedKeys bool     `toml:"authorized_keys"`
}

type NetCfg struct {
	Enabled      bool `toml:"enabled"`
	IntervalMs   int  `toml:"interval_ms"`
	Listen       bool `toml:"listen"`
	Outbound     bool `toml:"outbound"`
	OnlySessions bool `toml:"only_sessions"`
}

type SystemCfg struct {
	Enabled      bool     `toml:"enabled"`
	Clock        bool     `toml:"clock"`
	Modules      bool     `toml:"modules"`
	Mounts       bool     `toml:"mounts"`
	IgnoreMounts []string `toml:"ignore_mounts"`
}

type RemoteCfg struct {
	Enabled       bool   `toml:"enabled"`
	Address       string `toml:"address"`
	Key           string `toml:"key"`
	QueueSize     int    `toml:"queue_size"`
	HeartbeatSecs int    `toml:"heartbeat_secs"`
}

type ReceiverCfg struct {
	Listen          string `toml:"listen"`
	Key             string `toml:"key"`
	Dir             string `toml:"dir"`
	SilentAfterSecs int    `toml:"silent_after_secs"`
}

func Default() *Config {
	return &Config{
		Log: LogCfg{Dir: "/var/log/loger", MaxSizeMB: 50, Keep: 20, Harden: true},
		Exec: ExecCfg{
			Enabled:        true,
			OnlySessions:   true,
			IgnoreExe:      []string{},
			MaxArgsLen:     4096,
			PollIntervalMs: 500,
		},
		Auth: AuthCfg{
			Enabled:             true,
			Files:               []string{"/var/log/auth.log", "/var/log/secure"},
			BruteforceThreshold: 10,
		},
		Files: FilesCfg{
			Enabled: true,
			Watch: []string{
				"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
				"/etc/sudoers", "/etc/sudoers.d", "/etc/ssh", "/etc/pam.d",
				"/etc/crontab", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
				"/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron",
				"/etc/systemd/system", "/etc/ld.so.preload", "/etc/ld.so.conf.d",
				"/etc/hosts", "/etc/profile.d", "/etc/rc.local",
			},
			WatchReads:     []string{},
			AuthorizedKeys: true,
		},
		Net: NetCfg{Enabled: true, IntervalMs: 2000, Listen: true, Outbound: true, OnlySessions: true},
		System: SystemCfg{
			Enabled: true,
			Clock:   true,
			Modules: true,
			Mounts:  true,
			IgnoreMounts: []string{
				"/proc", "/sys", "/dev", "/run/user/", "/run/docker", "/run/netns",
				"/run/snapd", "/var/lib/docker", "/var/lib/containers", "/snap/", "/run/credentials",
			},
		},
		Remote:   RemoteCfg{QueueSize: 20000, HeartbeatSecs: 30},
		Receiver: ReceiverCfg{Listen: "0.0.0.0:6514", Dir: "/var/log/loger-remote", SilentAfterSecs: 120},
	}
}

func Parse(text []byte) (*Config, error) {
	c := Default()
	dec := toml.NewDecoder(bytes.NewReader(text))
	dec.DisallowUnknownFields()
	if err := dec.Decode(c); err != nil {
		var sm *toml.StrictMissingError
		var de *toml.DecodeError
		switch {
		case errors.As(err, &sm):
			var keys []string
			for _, e := range sm.Errors {
				row, _ := e.Position()
				keys = append(keys, fmt.Sprintf("%s (linha %d)", strings.Join(e.Key(), "."), row))
			}
			return nil, fmt.Errorf("campo desconhecido: %s", strings.Join(keys, ", "))
		case errors.As(err, &de):
			row, _ := de.Position()
			return nil, fmt.Errorf("linha %d: %v", row, de)
		}
		return nil, err
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) validate() error {
	for i, r := range c.Exec.Ignore {
		if r == (IgnoreRule{}) {
			return fmt.Errorf("exec.ignore[%d]: regra vazia ignoraria todos os comandos", i)
		}
		for name, pat := range map[string]string{"exe": r.Exe, "user": r.User, "parent": r.Parent} {
			if _, err := path.Match(pat, ""); err != nil {
				return fmt.Errorf("exec.ignore[%d].%s: padrão inválido %q", i, name, pat)
			}
		}
	}
	return nil
}

// Load carrega o arquivo. Se explicit for falso e o arquivo não existir, usa os padrões.
func Load(path string, explicit bool) (*Config, error) {
	text, err := os.ReadFile(path)
	if os.IsNotExist(err) && !explicit {
		return Default(), nil
	}
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("arquivo de configuração não encontrado: %s", path)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	c, err := Parse(text)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	return c, nil
}
