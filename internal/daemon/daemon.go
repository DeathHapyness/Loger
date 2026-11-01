package daemon

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/DeathHapyness/loger/internal/collectors"
	"github.com/DeathHapyness/loger/internal/config"
	"github.com/DeathHapyness/loger/internal/event"
	"github.com/DeathHapyness/loger/internal/store"
	"github.com/DeathHapyness/loger/internal/util"
	"golang.org/x/sys/unix"
)

type Options struct {
	ConfigPath string
	Explicit   bool
	Version    string
}

// lockDir garante uma única instância por diretório de log (duas quebrariam a corrente).
func lockDir(dir string) (*os.File, error) {
	_ = os.MkdirAll(dir, 0o700)
	f, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_WRONLY|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("%s: %v (rode como root?)", dir, err)
	}
	if unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		f.Close()
		return nil, fmt.Errorf("já existe um loger daemon rodando com este diretório de log")
	}
	return f, nil
}

func startEvents(st *store.Store, cfg *config.Config, version string) []event.Ev {
	var uptime uint64
	if s, ok := util.ReadText("/proc/uptime", 64); ok {
		uptime, _ = strconv.ParseUint(strings.SplitN(s, ".", 2)[0], 10, 64)
	}
	kernel, _ := util.ReadText("/proc/sys/kernel/osrelease", 128)
	kernel = strings.TrimSpace(kernel)
	evs := []event.Ev{
		event.New("loger.start", event.Info, fmt.Sprintf("Loger %s iniciado (kernel %s, ligado há %ds)", version, kernel, uptime)).
			WithData(event.D{"pid": os.Getpid(), "kernel": kernel, "uptime_secs": uptime, "remote": cfg.Remote.Enabled}),
	}
	if st.LastKind != "" && st.LastKind != "loger.stop" {
		evs = append(evs, event.New("loger.unclean_stop", event.Warn, fmt.Sprintf(
			"a execução anterior terminou sem desligamento limpo (último evento: %s em %s) — kill -9, crash ou queda de energia",
			st.LastKind, st.LastTs)))
	}
	return evs
}

// needsRestart lista as mudanças de configuração que só valem depois de reiniciar o daemon.
func needsRestart(old, cur *config.Config) []string {
	var out []string
	if old.Log != cur.Log {
		out = append(out, "[log]")
	}
	if !reflect.DeepEqual(collectors.Enabled(old), collectors.Enabled(cur)) {
		out = append(out, "coletores ligados/desligados")
	}
	if old.Remote != cur.Remote {
		out = append(out, "[remote]")
	}
	return out
}

func reload(opts Options, cfg *atomic.Pointer[config.Config]) event.Ev {
	cur, err := config.Load(opts.ConfigPath, opts.Explicit)
	if err != nil {
		return event.New("loger.reload", event.Warn, fmt.Sprintf("configuração NÃO recarregada: %v", err))
	}
	old := cfg.Swap(cur)
	msg := "configuração recarregada"
	if r := needsRestart(old, cur); len(r) > 0 {
		msg += " (mudanças em " + strings.Join(r, ", ") + " só valem depois de reiniciar)"
	}
	return event.New("loger.reload", event.Notice, msg)
}

func Run(cfg0 *config.Config, opts Options) error {
	if !util.IsRoot() {
		fmt.Fprintln(os.Stderr, "loger: aviso: rodando sem root — vários coletores vão funcionar parcialmente")
	}
	dir := cfg0.Log.Dir
	lock, err := lockDir(dir)
	if err != nil {
		return err
	}
	defer lock.Close()
	st, err := store.Open(dir, cfg0.Log.MaxSizeMB, cfg0.Log.Keep, cfg0.Log.Harden, util.Hostname())
	if err != nil {
		return fmt.Errorf("%s: %v", dir, err)
	}

	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)

	var cfg atomic.Pointer[config.Config]
	cfg.Store(cfg0)
	events := make(chan event.Ev, 8192)

	write := func(ev event.Ev) {
		if _, err := st.Append(ev); err != nil {
			fmt.Fprintln(os.Stderr, "loger: falha ao gravar:", err)
		}
	}
	for _, ev := range startEvents(st, cfg0, opts.Version) {
		write(ev)
	}
	collectors.StartAll(collectors.NewCtx(events, &cfg))

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case ev := <-events:
			write(ev)
		case <-tick.C:
			if ev, bad := st.Tick(); bad {
				write(ev)
			}
		case sig := <-sigs:
			if sig == syscall.SIGHUP {
				write(reload(opts, &cfg))
				continue
			}
			for drained := false; !drained; {
				select {
				case ev := <-events:
					write(ev)
				default:
					drained = true
				}
			}
			name := "SIGINT"
			if sig == syscall.SIGTERM {
				name = "SIGTERM"
			}
			write(event.New("loger.stop", event.Warn, fmt.Sprintf("Loger parado (%s)", name)))
			return st.Log.Close()
		}
	}
}
