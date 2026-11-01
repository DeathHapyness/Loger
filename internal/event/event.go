package event

import (
	"bytes"
	"encoding/json"
	"strconv"

	"github.com/DeathHapyness/loger/internal/util"
)

const (
	Info   = "info"
	Notice = "notice"
	Warn   = "warn"
	Alert  = "alert"
)

const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

func LevelRank(l string) int {
	switch l {
	case Notice:
		return 1
	case Warn:
		return 2
	case Alert:
		return 3
	}
	return 0
}

type D = map[string]any

// Ev é o que os coletores produzem; o escritor transforma em Record.
type Ev struct {
	TsMs  int64
	Kind  string
	Level string
	User  string
	Msg   string
	Data  any
}

func New(kind, level, msg string) Ev {
	return Ev{TsMs: util.NowMs(), Kind: kind, Level: level, Msg: msg}
}

func (e Ev) WithUser(u string) Ev {
	e.User = u
	return e
}

func (e Ev) WithData(d any) Ev {
	e.Data = d
	return e
}

type Record struct {
	Seq   uint64          `json:"seq"`
	Ts    string          `json:"ts"`
	Host  string          `json:"host"`
	Kind  string          `json:"kind"`
	Level string          `json:"level"`
	User  string          `json:"user"`
	Msg   string          `json:"msg"`
	Data  json.RawMessage `json:"data"`
	Prev  string          `json:"prev"`
	Hash  string          `json:"hash"`
}

func FromEv(ev Ev, seq uint64, host, prev string) Record {
	r := Record{
		Seq:   seq,
		Ts:    util.FmtUTC(ev.TsMs),
		Host:  host,
		Kind:  ev.Kind,
		Level: ev.Level,
		User:  ev.User,
		Msg:   ev.Msg,
		Data:  encodeValue(ev.Data),
		Prev:  prev,
	}
	r.Hash = r.ComputeHash()
	return r
}

func (r *Record) hasData() bool {
	return len(r.Data) > 0 && !bytes.Equal(r.Data, []byte("null"))
}

func (r *Record) encode(withHash bool) []byte {
	b := make([]byte, 0, 256+len(r.Msg)+len(r.Data))
	b = append(b, `{"seq":`...)
	b = strconv.AppendUint(b, r.Seq, 10)
	b = append(b, `,"ts":`...)
	b = appendString(b, r.Ts)
	b = append(b, `,"host":`...)
	b = appendString(b, r.Host)
	b = append(b, `,"kind":`...)
	b = appendString(b, r.Kind)
	b = append(b, `,"level":`...)
	b = appendString(b, r.Level)
	if r.User != "" {
		b = append(b, `,"user":`...)
		b = appendString(b, r.User)
	}
	b = append(b, `,"msg":`...)
	b = appendString(b, r.Msg)
	if r.hasData() {
		b = append(b, `,"data":`...)
		b = append(b, r.Data...)
	}
	b = append(b, `,"prev":`...)
	b = appendString(b, r.Prev)
	if withHash && r.Hash != "" {
		b = append(b, `,"hash":`...)
		b = appendString(b, r.Hash)
	}
	return append(b, '}')
}

// ComputeHash é o sha256 do registro sem o campo hash. Como prev entra no cálculo,
// alterar ou remover qualquer registro quebra a corrente a partir dali.
func (r *Record) ComputeHash() string {
	return util.Sha256Hex(r.encode(false))
}

func (r *Record) Line() []byte {
	return r.encode(true)
}

func (r *Record) TsMs() int64 {
	ms, _ := util.ParseUTC(r.Ts)
	return ms
}

// Ses devolve o campo data.ses, que liga o evento a uma sessão de login.
func (r *Record) Ses() (uint64, bool) {
	if !r.hasData() || !bytes.Contains(r.Data, []byte(`"ses":`)) {
		return 0, false
	}
	return topLevelUint(r.Data, "ses")
}
