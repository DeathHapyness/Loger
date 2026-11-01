package collectors

// Sistema: mudança de hora, módulos do kernel e montagens.

import (
	"fmt"
	"strings"
	"time"

	"github.com/DeathHapyness/loger/internal/config"
	"github.com/DeathHapyness/loger/internal/event"
	"github.com/DeathHapyness/loger/internal/util"
	"golang.org/x/sys/unix"
)

func init() {
	register("system", func(c *config.Config) bool { return c.System.Enabled }, runSystem)
}

func modules() map[string]bool {
	text, _ := util.ReadText("/proc/modules", 1<<20)
	m := map[string]bool{}
	for _, l := range strings.Split(text, "\n") {
		if f := strings.Fields(l); len(f) > 0 {
			m[f[0]] = true
		}
	}
	return m
}

type mount struct {
	src, fstype string
}

// mountsFile é a tabela do namespace de montagens do init: dentro de um container com
// pid: host é a do host, e não a do próprio container.
var mountsFile = func() string {
	if fd, err := unix.Open("/proc/1/mounts", unix.O_RDONLY|unix.O_CLOEXEC, 0); err == nil {
		unix.Close(fd)
		return "/proc/1/mounts"
	}
	return "/proc/self/mounts"
}()

func mounts(ignore []string) map[string]mount {
	text, _ := util.ReadText(mountsFile, 1<<20)
	m := map[string]mount{}
	for _, l := range strings.Split(text, "\n") {
		f := strings.Fields(l)
		if len(f) < 3 {
			continue
		}
		mnt := strings.ReplaceAll(f[1], `\040`, " ")
		skip := false
		for _, i := range ignore {
			if strings.HasPrefix(mnt, i) {
				skip = true
				break
			}
		}
		if !skip {
			m[mnt] = mount{f[0], f[2]}
		}
	}
	return m
}

func runSystem(ctx Ctx) {
	if ctx.Cfg().System.Clock {
		go watchClock(ctx)
	}
	cfg := ctx.Cfg().System
	mods, mnts := modules(), mounts(cfg.IgnoreMounts)

	// O kernel sinaliza POLLPRI na tabela de montagens quando a tabela de montagens muda,
	// então montagens são vistas na hora; módulos não têm aviso e são conferidos a cada 3s.
	// Abre com unix.Open: o os.Open registraria o arquivo no epoll do runtime, que consome
	// o aviso antes do poll daqui.
	var fds []unix.PollFd
	if fd, err := unix.Open(mountsFile, unix.O_RDONLY|unix.O_CLOEXEC, 0); err == nil {
		defer unix.Close(fd)
		fds = []unix.PollFd{{Fd: int32(fd), Events: unix.POLLPRI | unix.POLLERR}}
	}
	lastMods := time.Now()
	for {
		mountChanged := false
		if fds != nil {
			wait := max(3*time.Second-time.Since(lastMods), 0)
			n, err := unix.Poll(fds, int(wait.Milliseconds()))
			mountChanged = err == nil && n > 0
		} else {
			time.Sleep(3 * time.Second)
			mountChanged = true
		}
		cfg := ctx.Cfg().System
		if time.Since(lastMods) >= 3*time.Second {
			lastMods = time.Now()
			if cfg.Modules {
				now := modules()
				for _, m := range sortedMapKeys(now) {
					if !mods[m] {
						ctx.Send(event.New("kernel.module_loaded", event.Warn, "módulo do kernel carregado: "+m).WithData(event.D{"module": m}))
					}
				}
				for _, m := range sortedMapKeys(mods) {
					if !now[m] {
						ctx.Send(event.New("kernel.module_unloaded", event.Notice, "módulo do kernel removido: "+m).WithData(event.D{"module": m}))
					}
				}
				mods = now
			}
		}
		if cfg.Mounts && mountChanged {
			now := mounts(cfg.IgnoreMounts)
			for _, mnt := range sortedMapKeys(now) {
				if old, ok := mnts[mnt]; !ok || old != now[mnt] {
					m := now[mnt]
					ctx.Send(event.New("mount.added", event.Notice, fmt.Sprintf("%s (%s) montado em %s", m.src, m.fstype, mnt)).
						WithData(event.D{"source": m.src, "fstype": m.fstype, "mountpoint": mnt}))
				}
			}
			for _, mnt := range sortedMapKeys(mnts) {
				if _, ok := now[mnt]; !ok {
					m := mnts[mnt]
					ctx.Send(event.New("mount.removed", event.Info, fmt.Sprintf("%s desmontado de %s", m.src, mnt)).
						WithData(event.D{"source": m.src, "fstype": m.fstype, "mountpoint": mnt}))
				}
			}
			mnts = now
		}
	}
}

// watchClock usa um timerfd com TFD_TIMER_CANCEL_ON_SET: o kernel acorda a leitura sempre
// que alguém ajusta o relógio do sistema (date -s, settimeofday, clock_settime).
func watchClock(ctx Ctx) {
	fd, err := unix.TimerfdCreate(unix.CLOCK_REALTIME, unix.TFD_CLOEXEC)
	if err != nil {
		return
	}
	defer unix.Close(fd)
	offset := func() int64 {
		var mono unix.Timespec
		unix.ClockGettime(unix.CLOCK_MONOTONIC, &mono)
		return util.NowMs() - (mono.Sec*1000 + mono.Nsec/1_000_000)
	}
	buf := make([]byte, 8)
	for {
		base := offset()
		spec := unix.ItimerSpec{Value: unix.Timespec{Sec: util.NowMs()/1000 + 10*365*86400}}
		if unix.TimerfdSettime(fd, unix.TFD_TIMER_ABSTIME|unix.TFD_TIMER_CANCEL_ON_SET, &spec, nil) != nil {
			return
		}
		_, err := unix.Read(fd, buf)
		if err == unix.EINTR {
			continue
		}
		if err != unix.ECANCELED {
			continue
		}
		delta := (offset() - base) / 1000
		if delta >= 2 || delta <= -2 {
			level := event.Warn
			if delta > 300 || delta < -300 {
				level = event.Alert
			}
			dir := "atrasado"
			if delta > 0 {
				dir = "adiantado"
			}
			abs := max(delta, -delta)
			ctx.Send(event.New("system.clock_changed", level, fmt.Sprintf("relógio do sistema %s em %ds", dir, abs)).
				WithData(event.D{"delta_secs": delta}))
		}
	}
}
