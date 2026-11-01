package collectors

import (
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// fileWaiter acorda quando um arquivo é escrito, trocado ou recriado. Vigia o arquivo e o
// diretório dele (para pegar a rotação). Sem inotify, espera 500 ms.
type fileWaiter struct {
	fd     int
	path   string
	fileWD int
	buf    []byte
}

func newFileWaiter(path string) *fileWaiter {
	w := &fileWaiter{fd: -1, path: path, fileWD: -1}
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return w
	}
	w.fd = fd
	w.buf = make([]byte, 16*1024)
	_, _ = unix.InotifyAddWatch(fd, filepath.Dir(path), unix.IN_CREATE|unix.IN_MOVED_TO|unix.IN_MOVED_FROM|unix.IN_DELETE)
	w.rewatch()
	return w
}

// rewatch passa a vigiar o arquivo que está no caminho agora (depois de uma rotação).
func (w *fileWaiter) rewatch() {
	if w.fd < 0 {
		return
	}
	if w.fileWD >= 0 {
		_, _ = unix.InotifyRmWatch(w.fd, uint32(w.fileWD))
		w.fileWD = -1
	}
	mask := uint32(unix.IN_MODIFY | unix.IN_ATTRIB | unix.IN_CLOSE_WRITE | unix.IN_MOVE_SELF | unix.IN_DELETE_SELF)
	if wd, err := unix.InotifyAddWatch(w.fd, w.path, mask); err == nil {
		w.fileWD = wd
	}
}

// Wait volta quando houver alguma mudança ou depois de max.
func (w *fileWaiter) Wait(max time.Duration) {
	if w.fd < 0 {
		time.Sleep(500 * time.Millisecond)
		return
	}
	fds := []unix.PollFd{{Fd: int32(w.fd), Events: unix.POLLIN}}
	n, err := unix.Poll(fds, int(max.Milliseconds()))
	if err != nil && err != unix.EINTR {
		time.Sleep(500 * time.Millisecond)
		return
	}
	if n > 0 {
		for {
			if _, err := unix.Read(w.fd, w.buf); err != nil {
				break
			}
		}
	}
}

func (w *fileWaiter) Close() {
	if w.fd >= 0 {
		unix.Close(w.fd)
	}
}

func inodeStat(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}

func inodeOf(f *os.File) uint64 {
	fi, err := f.Stat()
	if err != nil {
		return 0
	}
	return inodeStat(fi)
}
