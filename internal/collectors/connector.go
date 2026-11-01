package collectors

import (
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"github.com/DeathHapyness/loger/internal/event"
	"github.com/DeathHapyness/loger/internal/procfs"
	"golang.org/x/sys/unix"
)

const (
	cnIdxProc          = 1
	cnValProc          = 1
	procCnMcastListen  = 1
	procEvFork         = 0x1
	procEvExec         = 0x2
	procEvUID          = 0x4
	procEvPtrace       = 0x100
	procEvExit         = 0x80000000
	nlmsgHdrLen        = 16
	cnMsgLen           = 20
	procEventHeaderLen = 16
)

func openConnector() (int, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_CONNECTOR)
	if err != nil {
		return -1, err
	}
	// Buffer grande para aguentar rajadas (compilação, fork bomb).
	if unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, 8<<20) != nil {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 8<<20)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: cnIdxProc}); err != nil {
		unix.Close(fd)
		return -1, err
	}
	// nlmsghdr (16) + cn_msg (20) + operação (4)
	msg := make([]byte, 40)
	binary.NativeEndian.PutUint32(msg[0:], 40)
	binary.NativeEndian.PutUint16(msg[4:], unix.NLMSG_DONE)
	binary.NativeEndian.PutUint32(msg[12:], uint32(os.Getpid()))
	binary.NativeEndian.PutUint32(msg[16:], cnIdxProc)
	binary.NativeEndian.PutUint32(msg[20:], cnValProc)
	binary.NativeEndian.PutUint16(msg[32:], 4)
	binary.NativeEndian.PutUint32(msg[36:], procCnMcastListen)
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func u32At(b []byte, off int) uint32 {
	if off < 0 || off+4 > len(b) {
		return 0
	}
	return binary.NativeEndian.Uint32(b[off:])
}

func runConnector(t *tracker, fd int) {
	defer unix.Close(fd)
	buf := make([]byte, 16*1024)
	var lost uint64
	lastLost, lastHK := time.Now(), time.Now()
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for {
		if n, err := unix.Poll(fds, 1000); err == nil && n > 0 {
			n, _, err := unix.Recvfrom(fd, buf, 0)
			switch {
			case err == unix.ENOBUFS:
				lost++
			case err == nil:
				handleDatagram(t, buf[:n])
			}
		}
		if lost > 0 && time.Since(lastLost) > 10*time.Second {
			t.ctx.Send(event.New("loger.events_lost", event.Warn,
				fmt.Sprintf("o kernel descartou eventos de processo %d vez(es) por excesso de volume", lost)))
			lost = 0
			lastLost = time.Now()
		}
		if time.Since(lastHK) >= time.Second {
			t.housekeeping()
			lastHK = time.Now()
		}
	}
}

func handleDatagram(t *tracker, buf []byte) {
	for off := 0; off+nlmsgHdrLen <= len(buf); {
		l := int(u32At(buf, off))
		if l < nlmsgHdrLen || off+l > len(buf) {
			return
		}
		// payload = cn_msg + proc_event; os dados do evento começam depois do cabeçalho dele
		start := off + nlmsgHdrLen + cnMsgLen
		if start > off+l {
			return
		}
		ev := buf[start : off+l]
		what := u32At(ev, 0)
		d := procEventHeaderLen
		a, b := int(int32(u32At(ev, d))), int(int32(u32At(ev, d+4)))
		switch {
		case what == procEvFork:
			childPID, childTGID := int(int32(u32At(ev, d+8))), int(int32(u32At(ev, d+12)))
			if childPID == childTGID {
				t.onFork(b, childTGID)
			}
		case what == procEvExec && a == b:
			t.onExec(b)
		case what == procEvUID && a == b:
			t.onUID(b, u32At(ev, d+8), u32At(ev, d+12))
		case what == procEvPtrace:
			t.onPtrace(b, int(int32(u32At(ev, d+12))))
		case what == procEvExit && a == b:
			t.onExit(b)
		}
		off += (l + 3) &^ 3
	}
}

func runPolling(t *tracker) {
	interval := time.Duration(max(t.ctx.Cfg().Exec.PollIntervalMs, 100)) * time.Millisecond
	for {
		time.Sleep(interval)
		pids := procfs.AllPIDs()
		current := make(map[int]bool, len(pids))
		for _, pid := range pids {
			current[pid] = true
			start, ok := procfs.StartTime(pid)
			if p, known := t.procs[pid]; !known || !ok || p.start != start {
				delete(t.procs, pid)
				t.onExec(pid)
			}
		}
		for pid := range t.procs {
			if !current[pid] {
				t.onExit(pid)
			}
		}
		t.housekeeping()
	}
}
