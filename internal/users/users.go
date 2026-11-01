package users

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/DeathHapyness/loger/internal/procfs"
)

// Users traduz uid em nome lendo /etc/passwd direto (sem NSS), e relê o arquivo quando
// ele muda. Não é seguro para uso concorrente: cada coletor tem o seu.
type Users struct {
	names   map[uint32]string
	mtime   time.Time
	checked time.Time
}

func New() *Users {
	u := &Users{}
	u.reload()
	return u
}

func passwdMtime() time.Time {
	st, err := os.Stat("/etc/passwd")
	if err != nil {
		return time.Time{}
	}
	return st.ModTime()
}

func (u *Users) reload() {
	u.mtime = passwdMtime()
	u.checked = time.Now()
	u.names = map[uint32]string{}
	for _, e := range Entries() {
		u.names[e.UID] = e.Name
	}
}

func (u *Users) Name(uid uint32) string {
	if uid == procfs.NoID {
		return ""
	}
	if time.Since(u.checked) > 5*time.Second {
		u.checked = time.Now()
		if !passwdMtime().Equal(u.mtime) {
			u.reload()
		}
	}
	if n, ok := u.names[uid]; ok {
		return n
	}
	return "uid:" + strconv.FormatUint(uint64(uid), 10)
}

type Entry struct {
	Name  string
	UID   uint32
	Home  string
	Shell string
}

func Entries() []Entry {
	text, _ := os.ReadFile("/etc/passwd")
	var out []Entry
	for _, l := range strings.Split(string(text), "\n") {
		f := strings.Split(l, ":")
		if len(f) < 7 {
			continue
		}
		uid, err := strconv.ParseUint(f[2], 10, 32)
		if err != nil {
			continue
		}
		out = append(out, Entry{Name: f[0], UID: uint32(uid), Home: f[5], Shell: f[6]})
	}
	return out
}
