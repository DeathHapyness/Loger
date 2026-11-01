package event

import (
	"bytes"
	"encoding/json"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// O hash de cada registro é calculado sobre o JSON gerado pela versão em Rust (serde_json),
// então a serialização precisa produzir exatamente os mesmos bytes: chaves de objeto em
// ordem, sem espaços, só aspas, barra e caracteres de controle escapados.

const hexDigits = "0123456789abcdef"

func appendString(b []byte, s string) []byte {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	b = append(b, '"')
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c != '"' && c != '\\' {
			continue
		}
		b = append(b, s[start:i]...)
		switch c {
		case '"':
			b = append(b, '\\', '"')
		case '\\':
			b = append(b, '\\', '\\')
		case '\b':
			b = append(b, '\\', 'b')
		case '\f':
			b = append(b, '\\', 'f')
		case '\n':
			b = append(b, '\\', 'n')
		case '\r':
			b = append(b, '\\', 'r')
		case '\t':
			b = append(b, '\\', 't')
		default:
			b = append(b, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
		}
		start = i + 1
	}
	b = append(b, s[start:]...)
	return append(b, '"')
}

func appendFloat(b []byte, f float64) []byte {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return append(b, "null"...)
	}
	if f == math.Trunc(f) && math.Abs(f) < 1e16 {
		return append(strconv.AppendInt(b, int64(f), 10), '.', '0')
	}
	return append(b, strings.Replace(strconv.FormatFloat(f, 'g', -1, 64), "e+", "e", 1)...)
}

func appendValue(b []byte, v any) []byte {
	switch x := v.(type) {
	case nil:
		return append(b, "null"...)
	case string:
		return appendString(b, x)
	case bool:
		return strconv.AppendBool(b, x)
	case int:
		return strconv.AppendInt(b, int64(x), 10)
	case int32:
		return strconv.AppendInt(b, int64(x), 10)
	case int64:
		return strconv.AppendInt(b, x, 10)
	case uint16:
		return strconv.AppendUint(b, uint64(x), 10)
	case uint32:
		return strconv.AppendUint(b, uint64(x), 10)
	case uint64:
		return strconv.AppendUint(b, x, 10)
	case float64:
		return appendFloat(b, x)
	case json.Number:
		return append(b, x...)
	case json.RawMessage:
		return append(b, x...)
	case []string:
		b = append(b, '[')
		for i, s := range x {
			if i > 0 {
				b = append(b, ',')
			}
			b = appendString(b, s)
		}
		return append(b, ']')
	case []any:
		b = append(b, '[')
		for i, e := range x {
			if i > 0 {
				b = append(b, ',')
			}
			b = appendValue(b, e)
		}
		return append(b, ']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b = append(b, '{')
		for i, k := range keys {
			if i > 0 {
				b = append(b, ',')
			}
			b = appendString(b, k)
			b = append(b, ':')
			b = appendValue(b, x[k])
		}
		return append(b, '}')
	}
	// Outros tipos (structs, slices de outros tipos): passa pelo encoding/json e normaliza.
	raw, err := json.Marshal(v)
	if err != nil {
		return append(b, "null"...)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic any
	if dec.Decode(&generic) != nil {
		return append(b, "null"...)
	}
	return appendValue(b, normalize(generic))
}

func normalize(v any) any {
	switch x := v.(type) {
	case []any:
		for i := range x {
			x[i] = normalize(x[i])
		}
	case map[string]any:
		for k := range x {
			x[k] = normalize(x[k])
		}
	}
	return v
}

func encodeValue(v any) json.RawMessage {
	if v == nil {
		return nil
	}
	return appendValue(nil, v)
}
