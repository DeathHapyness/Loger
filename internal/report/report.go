package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/DeathHapyness/loger/internal/event"
	"github.com/DeathHapyness/loger/internal/store"
	"github.com/DeathHapyness/loger/internal/util"
)

type Options struct {
	Since int64
	Until int64
	Top   int
	JSON  bool
}

func Parse(args []string) (Options, error) {
	o := Options{Top: 10}
	o.Since, _ = util.ParseWhen("24h")
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--json" {
			o.JSON = true
			continue
		}
		if i+1 >= len(args) {
			return o, fmt.Errorf("%s precisa de um valor", a)
		}
		i++
		v := args[i]
		switch a {
		case "-s", "--since", "--until":
			ms, ok := util.ParseWhen(v)
			if !ok {
				return o, fmt.Errorf("data inválida em %s", a)
			}
			if a == "--until" {
				o.Until = ms
			} else {
				o.Since = ms
			}
		case "-n":
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 {
				return o, fmt.Errorf("-n precisa de um número")
			}
			o.Top = n
		case "-d", "--dir", "-c", "--config":
		default:
			return o, fmt.Errorf("opção desconhecida: %s", a)
		}
	}
	return o, nil
}

type Count struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

type Item struct {
	Ts    string `json:"ts"`
	Kind  string `json:"kind"`
	Level string `json:"level"`
	User  string `json:"user,omitempty"`
	Msg   string `json:"msg"`
}

type Report struct {
	Host       string         `json:"host"`
	Since      string         `json:"since"`
	Until      string         `json:"until"`
	Records    int            `json:"records"`
	Levels     map[string]int `json:"levels"`
	Logins     []Count        `json:"logins"`
	SSHAccepts []Count        `json:"ssh_accepts"`
	FailIPs    []Count        `json:"failed_login_ips"`
	FailUsers  []Count        `json:"failed_login_users"`
	Bruteforce []Item         `json:"bruteforce"`
	Privilege  []Item         `json:"privilege"`
	PrivCmds   []Count        `json:"privileged_commands"`
	Alerts     []Item         `json:"alerts"`
	AlertCount int            `json:"alert_count"`
	Ports      []Item         `json:"new_ports"`
	Outbound   []Count        `json:"outbound"`
	Changes    []Item         `json:"changes"`
	System     []Item         `json:"system"`
	Integrity  []Item         `json:"integrity"`
	CmdUsers   []Count        `json:"commands_by_user"`
	CmdBins    []Count        `json:"commands_by_binary"`
}

type counter map[string]int

func (c counter) top(n int) []Count {
	out := make([]Count, 0, len(c))
	for k, v := range c {
		out = append(out, Count{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func item(r *event.Record) Item {
	return Item{Ts: r.Ts, Kind: r.Kind, Level: r.Level, User: r.User, Msg: r.Msg}
}

func dataOf(r *event.Record) map[string]any {
	var d map[string]any
	if len(r.Data) > 0 {
		json.Unmarshal(r.Data, &d)
	}
	return d
}

func str(d map[string]any, k string) string {
	if v, ok := d[k]; ok && v != nil {
		return fmt.Sprint(v)
	}
	return ""
}

func prefix(kind string, ps ...string) bool {
	for _, p := range ps {
		if kind == p || strings.HasPrefix(kind, p+".") {
			return true
		}
	}
	return false
}

const maxItems = 50

func appendLimited(list []Item, it Item) []Item {
	if len(list) < maxItems {
		return append(list, it)
	}
	return list
}

func Build(dir string, o Options) (*Report, error) {
	files := store.LogFiles(dir)
	if len(files) == 0 {
		return nil, store.NoLogs(dir)
	}
	files = store.FilesSince(files, o.Since)
	rep := &Report{Levels: map[string]int{}, Since: util.FmtLocal(o.Since), Until: "agora"}
	if o.Until > 0 {
		rep.Until = util.FmtLocal(o.Until)
	}
	logins, accepts, failIPs, failUsers := counter{}, counter{}, counter{}, counter{}
	privCmds, outbound, cmdUsers, cmdBins := counter{}, counter{}, counter{}, counter{}

	for _, path := range files {
		err := store.EachLine(path, func(_ int, line []byte) bool {
			r, err := event.Parse(line)
			if err != nil {
				return true
			}
			t := r.TsMs()
			if t < o.Since || (o.Until > 0 && t > o.Until) {
				return true
			}
			if rep.Host == "" {
				rep.Host = r.Host
			}
			rep.Records++
			rep.Levels[r.Level]++
			if r.Level == event.Alert {
				rep.AlertCount++
				rep.Alerts = appendLimited(rep.Alerts, item(&r))
			}
			k := r.Kind
			switch {
			case k == "session.start" || k == "session.active":
				d := dataOf(&r)
				key := r.User + " via " + str(d, "via")
				if from := str(d, "from"); from != "" {
					key += " de " + from
				}
				logins[key]++
			case k == "ssh.auth_ok":
				d := dataOf(&r)
				accepts[fmt.Sprintf("%s de %s (%s)", r.User, str(d, "ip"), str(d, "method"))]++
			case k == "ssh.auth_fail":
				failIPs[str(dataOf(&r), "ip")]++
				failUsers[r.User]++
			case k == "ssh.bruteforce":
				rep.Bruteforce = appendLimited(rep.Bruteforce, item(&r))
			case k == "priv.sudo_denied" || k == "priv.sudo_auth_fail" || k == "priv.su_fail" || k == "priv.escalation" || k == "proc.ptrace":
				rep.Privilege = appendLimited(rep.Privilege, item(&r))
			case k == "priv.cmd":
				privCmds[r.User]++
			case k == "net.listen":
				rep.Ports = appendLimited(rep.Ports, item(&r))
			case k == "net.connect" || k == "net.shell_socket":
				d := dataOf(&r)
				outbound[fmt.Sprintf("%s:%s", str(d, "remote"), str(d, "remote_port"))]++
			case prefix(k, "file", "account", "ssh.key_added", "ssh.key_removed"):
				rep.Changes = appendLimited(rep.Changes, item(&r))
			case prefix(k, "kernel.module_loaded", "kernel.module_unloaded", "mount.added", "mount.removed", "system", "firewall"):
				rep.System = appendLimited(rep.System, item(&r))
			case k == "loger.unclean_stop" || k == "loger.log_tampered" || k == "loger.events_lost" ||
				k == "loger.remote_dropped" || k == "loger.stop":
				rep.Integrity = appendLimited(rep.Integrity, item(&r))
			}
			if prefix(k, "exec", "priv.cmd", "account.cmd", "firewall.cmd", "kernel.module_cmd", "cron.cmd",
				"service.cmd", "mount.cmd", "ssh.transfer", "system.power_cmd") {
				cmdUsers[r.User]++
				cmdBins[util.Basename(str(dataOf(&r), "exe"))]++
			}
			return true
		})
		if err != nil {
			return nil, err
		}
	}
	n := o.Top
	rep.Logins, rep.SSHAccepts = logins.top(n), accepts.top(n)
	rep.FailIPs, rep.FailUsers = failIPs.top(n), failUsers.top(n)
	rep.PrivCmds, rep.Outbound = privCmds.top(n), outbound.top(n)
	rep.CmdUsers, rep.CmdBins = cmdUsers.top(n), cmdBins.top(n)
	return rep, nil
}

func Print(w io.Writer, rep *Report) {
	fmt.Fprintf(w, "Relatório do Loger — %s\n", rep.Host)
	fmt.Fprintf(w, "Período: %s até %s\n", rep.Since, rep.Until)
	fmt.Fprintf(w, "%d registros: %d alertas, %d avisos, %d notas, %d info\n",
		rep.Records, rep.Levels[event.Alert], rep.Levels[event.Warn], rep.Levels[event.Notice], rep.Levels[event.Info])

	counts := func(title string, cs []Count) {
		if len(cs) == 0 {
			return
		}
		fmt.Fprintf(w, "\n%s\n", title)
		for _, c := range cs {
			key := c.Key
			if key == "" {
				key = "-"
			}
			fmt.Fprintf(w, "  %6d  %s\n", c.Count, key)
		}
	}
	items := func(title string, its []Item, total int) {
		if len(its) == 0 {
			return
		}
		fmt.Fprintf(w, "\n%s\n", title)
		for _, it := range its {
			ms, _ := util.ParseUTC(it.Ts)
			user := ""
			if it.User != "" {
				user = it.User + ": "
			}
			fmt.Fprintf(w, "  %s  %s%s\n", util.FmtLocal(ms), user, it.Msg)
		}
		if total > len(its) {
			fmt.Fprintf(w, "  ... e mais %d (veja com loger show)\n", total-len(its))
		}
	}

	items(fmt.Sprintf("ALERTAS (%d)", rep.AlertCount), rep.Alerts, rep.AlertCount)
	counts("Logins (usuário, origem)", rep.Logins)
	counts("Logins SSH aceitos", rep.SSHAccepts)
	counts("Falhas de login por IP", rep.FailIPs)
	counts("Usuários tentados nas falhas", rep.FailUsers)
	items("Força bruta", rep.Bruteforce, len(rep.Bruteforce))
	items("Privilégios negados ou suspeitos", rep.Privilege, len(rep.Privilege))
	counts("Uso de sudo/su por usuário", rep.PrivCmds)
	items("Portas novas", rep.Ports, len(rep.Ports))
	counts("Conexões de saída por destino", rep.Outbound)
	items("Arquivos, contas e chaves alterados", rep.Changes, len(rep.Changes))
	items("Sistema", rep.System, len(rep.System))
	items("Integridade do Loger", rep.Integrity, len(rep.Integrity))
	counts("Comandos por usuário", rep.CmdUsers)
	counts("Binários mais executados", rep.CmdBins)
}
