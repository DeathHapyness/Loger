package util

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

func NowMs() int64 {
	return time.Now().UnixMilli()
}

// FmtUTC formata epoch em ms como 2026-10-04T12:00:01.123Z.
func FmtUTC(ms int64) string {
	return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z")
}

func ParseUTC(s string) (int64, bool) {
	if len(s) < 20 {
		return 0, false
	}
	t, err := time.Parse("2006-01-02T15:04:05", s[:19])
	if err != nil {
		return 0, false
	}
	ms := t.UnixMilli()
	if s[19] == '.' && len(s) >= 23 {
		if n, err := strconv.Atoi(s[20:23]); err == nil {
			ms += int64(n)
		}
	}
	return ms, true
}

func FmtLocal(ms int64) string {
	return time.UnixMilli(ms).Local().Format("2006-01-02 15:04:05")
}

// ParseWhen aceita "30s", "15m", "2h", "7d", "1w" (relativo a agora) ou
// "2026-10-04", "2026-10-04 13:00", "2026-10-04T13:00:05" (hora local).
func ParseWhen(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	units := map[byte]int64{'s': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 7 * 86400}
	if mult, ok := units[s[len(s)-1]]; ok {
		if n, err := strconv.ParseInt(s[:len(s)-1], 10, 64); err == nil && n >= 0 {
			return NowMs() - n*mult*1000, true
		}
	}
	s = strings.Replace(s, "T", " ", 1)
	for _, layout := range []string{"2006-01-02 15:04:05", "2006-01-02 15:04", "2006-01-02 15", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t.UnixMilli(), true
		}
	}
	return 0, false
}

func Sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ReadText lê no máximo limit bytes de um arquivo.
func ReadText(path string, limit int64) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit))
	if err != nil {
		return "", false
	}
	return string(b), true
}

// LastLine devolve a última linha não vazia lendo só o final do arquivo.
func LastLine(path string) ([]byte, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Size() == 0 {
		return nil, false
	}
	start := st.Size() - 256*1024
	if start < 0 {
		start = 0
	}
	buf := make([]byte, st.Size()-start)
	if _, err := f.ReadAt(buf, start); err != nil && err != io.EOF {
		return nil, false
	}
	lines := bytes.Split(buf, []byte{'\n'})
	for i := len(lines) - 1; i >= 0; i-- {
		if len(bytes.TrimSpace(lines[i])) > 0 {
			return lines[i], true
		}
	}
	return nil, false
}

func Hostname() string {
	if s, ok := ReadText("/proc/sys/kernel/hostname", 256); ok {
		if s = strings.TrimSpace(s); s != "" {
			return s
		}
	}
	return "desconhecido"
}

func IsRoot() bool {
	return os.Geteuid() == 0
}
