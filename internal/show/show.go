package show

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"

	"github.com/DeathHapyness/loger/internal/event"
	"github.com/DeathHapyness/loger/internal/store"
	"github.com/DeathHapyness/loger/internal/util"
	"golang.org/x/sys/unix"
)

type printer struct {
	w     *bufio.Writer
	json  bool
	color bool
}

func newPrinter(json bool) *printer {
	_, err := unix.IoctlGetTermios(int(os.Stdout.Fd()), unix.TCGETS)
	_, noColor := os.LookupEnv("NO_COLOR")
	return &printer{w: bufio.NewWriterSize(os.Stdout, 64*1024), json: json, color: err == nil && !noColor}
}

func (p *printer) print(r *event.Record, line []byte) {
	if p.json {
		p.w.Write(line)
		p.w.WriteByte('\n')
		return
	}
	c, lvl := "\x1b[2m", "info  "
	switch r.Level {
	case event.Alert:
		c, lvl = "\x1b[1;31m", "ALERTA"
	case event.Warn:
		c, lvl = "\x1b[33m", "AVISO "
	case event.Notice:
		c, lvl = "\x1b[36m", "NOTA  "
	}
	dim, rst := "\x1b[2m", "\x1b[0m"
	if !p.color {
		c, dim, rst = "", "", ""
	}
	ses := ""
	if s, ok := r.Ses(); ok {
		ses = fmt.Sprintf(" %s[ses %d]%s", dim, s, rst)
	}
	user := r.User
	if user == "" {
		user = "-"
	}
	fmt.Fprintf(p.w, "%s %s%s%s %-22s %-12s %s%s\n", util.FmtLocal(r.TsMs()), c, lvl, rst, r.Kind, user, r.Msg, ses)
}

func Show(dir string, f *Filter) error {
	files := store.LogFiles(dir)
	if len(files) == 0 {
		return fmt.Errorf("%v (rode como root?)", store.NoLogs(dir))
	}
	if f.Since > 0 {
		files = store.FilesSince(files, f.Since)
	}
	p := newPrinter(f.JSON)
	defer p.w.Flush()

	if f.Last > 0 {
		if err := showLast(files, f, p); err != nil {
			return fmt.Errorf("%v (rode como root?)", err)
		}
	} else {
		for _, path := range files {
			err := store.EachLine(path, func(_ int, line []byte) bool {
				if r, ok := f.Match(line); ok {
					p.print(&r, line)
				}
				return true
			})
			if err != nil {
				return fmt.Errorf("%v (rode como root?)", err)
			}
		}
	}
	if f.Follow {
		p.w.Flush()
		follow(files[len(files)-1], f, p)
	}
	return nil
}

// showLast lê do arquivo mais novo para o mais antigo e para assim que tiver N registros.
func showLast(files []string, f *Filter, p *printer) error {
	type hit struct {
		r    event.Record
		line []byte
	}
	var hits []hit
	for i := len(files) - 1; i >= 0 && len(hits) < f.Last; i-- {
		err := store.EachLineReverse(files[i], func(line []byte) bool {
			if r, ok := f.Match(line); ok {
				hits = append(hits, hit{r, append([]byte{}, line...)})
			}
			return len(hits) < f.Last
		})
		if err != nil {
			return err
		}
	}
	for i := len(hits) - 1; i >= 0; i-- {
		p.print(&hits[i].r, hits[i].line)
	}
	return nil
}

func inode(fi os.FileInfo) uint64 {
	return fi.Sys().(*syscall.Stat_t).Ino
}

func follow(path string, f *Filter, p *printer) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	st, err := file.Stat()
	if err != nil {
		return
	}
	ino := inode(st)
	file.Seek(0, io.SeekEnd)
	r := bufio.NewReaderSize(file, 64*1024)
	var partial []byte
	rotated := false
	for {
		chunk, err := r.ReadBytes('\n')
		if err == nil {
			line := append(partial, chunk[:len(chunk)-1]...)
			partial = nil
			if rec, ok := f.Match(line); ok {
				p.print(&rec, line)
				p.w.Flush()
			}
			continue
		}
		if err != io.EOF {
			return
		}
		partial = append(partial, chunk...)
		// Na rotação, só troca de arquivo depois de ler o que sobrou no antigo.
		if rotated {
			if nf, err := os.Open(path); err == nil {
				if st, err := nf.Stat(); err == nil {
					file.Close()
					file, ino, partial = nf, inode(st), nil
					r.Reset(file)
				} else {
					nf.Close()
				}
			}
			rotated = false
			continue
		}
		time.Sleep(300 * time.Millisecond)
		if st, err := os.Stat(path); err == nil && inode(st) != ino {
			rotated = true
		}
	}
}
