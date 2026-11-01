package remote

import (
	"fmt"
	"io"
	"net"
	"time"

	"github.com/DeathHapyness/loger/internal/config"
	"github.com/DeathHapyness/loger/internal/event"
	"github.com/DeathHapyness/loger/internal/util"
)

func dial(addr string) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	return c, nil
}

// Sender recebe as linhas já gravadas localmente e as copia para o receptor. Se o receptor
// estiver fora, guarda em memória até queue_size e reenvia quando a conexão voltar.
// Termina quando lines é fechado, depois de tentar mandar o que estiver na fila.
func Sender(cfg config.RemoteCfg, lines <-chan []byte, events chan<- event.Ev) {
	trySend := func(ev event.Ev) {
		select {
		case events <- ev:
		default:
		}
	}
	c, err := ParseKey(cfg.Key)
	if err != nil {
		events <- event.New("loger.remote", event.Alert, "envio remoto desativado: "+err.Error())
		for range lines {
		}
		return
	}
	host := util.Hostname()
	limit := max(cfg.QueueSize, 100)
	heartbeat := time.Duration(max(cfg.HeartbeatSecs, 5)) * time.Second
	var queue [][]byte
	var conn net.Conn
	// O receptor nunca manda nada: se a leitura terminar, a conexão caiu. Assim a queda é
	// vista na hora, sem esperar a próxima escrita falhar.
	var closed chan struct{}
	var dropped uint64
	nextTry := time.Now()
	backoff := time.Second
	lastHB := time.Time{}
	wasDown := false
	write := func(b []byte) error {
		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		return writeFrame(conn, c, b)
	}
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()

	for {
		select {
		case l, ok := <-lines:
			if !ok {
				if conn != nil {
					for _, q := range queue {
						if write(q) != nil {
							break
						}
					}
					conn.Close()
				}
				return
			}
			queue = append(queue, l)
		drain:
			for {
				select {
				case l, ok := <-lines:
					if !ok {
						break drain
					}
					queue = append(queue, l)
				default:
					break drain
				}
			}
		case <-tick.C:
		case <-closed:
			conn.Close()
			conn, closed = nil, nil
			wasDown = true
			nextTry = time.Now().Add(backoff)
			trySend(event.New("loger.remote", event.Warn, fmt.Sprintf("conexão com receptor %s caiu", cfg.Address)))
		}
		if n := len(queue) - limit; n > 0 {
			queue = append(queue[:0], queue[n:]...)
			dropped += uint64(n)
		}

		if conn == nil && !time.Now().Before(nextTry) {
			if nc, err := dial(cfg.Address); err == nil {
				conn = nc
				closed = make(chan struct{})
				go func(c net.Conn, done chan struct{}) {
					io.Copy(io.Discard, c)
					close(done)
				}(nc, closed)
				backoff = time.Second
				if wasDown {
					trySend(event.New("loger.remote", event.Notice, fmt.Sprintf("reconectado ao receptor %s (%d eventos na fila)", cfg.Address, len(queue))))
				}
				wasDown = false
			} else {
				if !wasDown {
					trySend(event.New("loger.remote", event.Warn, fmt.Sprintf("receptor %s inacessível: %v — guardando eventos em memória", cfg.Address, err)))
				}
				wasDown = true
				nextTry = time.Now().Add(backoff)
				backoff = min(backoff*2, time.Minute)
			}
		}
		if conn != nil {
			failed := false
			if time.Since(lastHB) >= heartbeat {
				hb := event.D{"heartbeat": true, "host": host, "ts": util.FmtUTC(util.NowMs())}
				failed = write(event.Encode(hb)) != nil
				lastHB = time.Now()
			}
			for !failed && len(queue) > 0 {
				if write(queue[0]) != nil {
					failed = true
				} else {
					queue = queue[1:]
				}
			}
			if failed {
				conn.Close()
				conn, closed = nil, nil
				wasDown = true
				nextTry = time.Now().Add(backoff)
				trySend(event.New("loger.remote", event.Warn, fmt.Sprintf("conexão com receptor %s caiu", cfg.Address)))
			}
		}
		if dropped > 0 {
			trySend(event.New("loger.remote_dropped", event.Alert, fmt.Sprintf("%d eventos descartados da fila de envio remoto (receptor fora por muito tempo)", dropped)))
			dropped = 0
		}
	}
}
