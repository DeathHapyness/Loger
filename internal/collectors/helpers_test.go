package collectors

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/DeathHapyness/loger/internal/config"
	"github.com/DeathHapyness/loger/internal/event"
)

func testCtx(c *config.Config) (Ctx, chan event.Ev) {
	if c == nil {
		c = config.Default()
	}
	var p atomic.Pointer[config.Config]
	p.Store(c)
	ch := make(chan event.Ev, 1000)
	return NewCtx(ch, &p), ch
}

func drain(ch chan event.Ev) []event.Ev {
	var out []event.Ev
	for {
		select {
		case ev := <-ch:
			out = append(out, ev)
		default:
			return out
		}
	}
}

// waitFor espera até chegar um evento do tipo kind.
func waitFor(t *testing.T, ch chan event.Ev, kind string) event.Ev {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case ev := <-ch:
			if ev.Kind == kind {
				return ev
			}
		case <-deadline:
			t.Fatalf("evento %s não chegou", kind)
		}
	}
}

func countKind(evs []event.Ev, kind string) int {
	n := 0
	for _, e := range evs {
		if e.Kind == kind {
			n++
		}
	}
	return n
}
