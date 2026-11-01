package collectors

import (
	"sort"
	"sync/atomic"

	"github.com/DeathHapyness/loger/internal/config"
	"github.com/DeathHapyness/loger/internal/event"
)

// Ctx é o que cada coletor recebe: o canal de eventos e a configuração atual, que pode
// ser trocada a qualquer momento por um SIGHUP.
type Ctx struct {
	out chan<- event.Ev
	cfg *atomic.Pointer[config.Config]
}

func NewCtx(out chan<- event.Ev, cfg *atomic.Pointer[config.Config]) Ctx {
	return Ctx{out: out, cfg: cfg}
}

func (c Ctx) Send(ev event.Ev) {
	c.out <- ev
}

func (c Ctx) Cfg() *config.Config {
	return c.cfg.Load()
}

type collector struct {
	name    string
	enabled func(*config.Config) bool
	run     func(Ctx)
}

var registry []collector

func register(name string, enabled func(*config.Config) bool, run func(Ctx)) {
	registry = append(registry, collector{name, enabled, run})
	sort.Slice(registry, func(i, j int) bool { return registry[i].name < registry[j].name })
}

// Enabled devolve o nome dos coletores ligados na configuração.
func Enabled(c *config.Config) []string {
	var names []string
	for _, col := range registry {
		if col.enabled(c) {
			names = append(names, col.name)
		}
	}
	return names
}

func StartAll(ctx Ctx) {
	c := ctx.Cfg()
	for _, col := range registry {
		if col.enabled(c) {
			go col.run(ctx)
		}
	}
}
