package event

import (
	"errors"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Parser próprio para Record: o show e o verify leem milhões de linhas e o encoding/json,
// por usar reflexão e validar a linha duas vezes, ficava com quase todo o tempo.

var errSyntax = errors.New("JSON inválido")

type scanner struct {
	b []byte
	i int
}

func (s *scanner) ws() {
	for s.i < len(s.b) {
		switch s.b[s.i] {
		case ' ', '\t', '\n', '\r':
			s.i++
		default:
			return
		}
	}
}

func (s *scanner) peek() byte {
	s.ws()
	if s.i < len(s.b) {
		return s.b[s.i]
	}
	return 0
}

func (s *scanner) eat(c byte) bool {
	if s.peek() == c {
		s.i++
		return true
	}
	return false
}

func hexVal(c byte) rune {
	switch {
	case c >= '0' && c <= '9':
		return rune(c - '0')
	case c >= 'a' && c <= 'f':
		return rune(c - 'a' + 10)
	case c >= 'A' && c <= 'F':
		return rune(c - 'A' + 10)
	}
	return -1
}

func (s *scanner) hex4() (rune, bool) {
	if s.i+4 > len(s.b) {
		return 0, false
	}
	var r rune
	for _, c := range s.b[s.i : s.i+4] {
		v := hexVal(c)
		if v < 0 {
			return 0, false
		}
		r = r<<4 | v
	}
	s.i += 4
	return r, true
}

func (s *scanner) str() (string, error) {
	if !s.eat('"') {
		return "", errSyntax
	}
	start := s.i
	for s.i < len(s.b) {
		c := s.b[s.i]
		if c == '"' {
			raw := s.b[start:s.i]
			s.i++
			if !utf8.Valid(raw) {
				return strings.ToValidUTF8(string(raw), "�"), nil
			}
			return string(raw), nil
		}
		if c == '\\' {
			break
		}
		if c < 0x20 {
			return "", errSyntax
		}
		s.i++
	}
	out := append([]byte{}, s.b[start:s.i]...)
	for s.i < len(s.b) {
		c := s.b[s.i]
		switch {
		case c == '"':
			s.i++
			if !utf8.Valid(out) {
				return strings.ToValidUTF8(string(out), "�"), nil
			}
			return string(out), nil
		case c < 0x20:
			return "", errSyntax
		case c != '\\':
			out = append(out, c)
			s.i++
			continue
		}
		s.i++
		if s.i >= len(s.b) {
			return "", errSyntax
		}
		e := s.b[s.i]
		s.i++
		switch e {
		case '"', '\\', '/':
			out = append(out, e)
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			r, ok := s.hex4()
			if !ok {
				return "", errSyntax
			}
			if utf16.IsSurrogate(r) {
				r2 := rune(utf8.RuneError)
				if s.i+1 < len(s.b) && s.b[s.i] == '\\' && s.b[s.i+1] == 'u' {
					s.i += 2
					lo, ok := s.hex4()
					if !ok {
						return "", errSyntax
					}
					r2 = utf16.DecodeRune(r, lo)
				}
				r = r2
			}
			out = utf8.AppendRune(out, r)
		default:
			return "", errSyntax
		}
	}
	return "", errSyntax
}

func (s *scanner) uint() (uint64, error) {
	s.ws()
	start := s.i
	var n uint64
	for s.i < len(s.b) && s.b[s.i] >= '0' && s.b[s.i] <= '9' {
		d := uint64(s.b[s.i] - '0')
		if n > (1<<64-1-d)/10 {
			return 0, errSyntax
		}
		n = n*10 + d
		s.i++
	}
	if s.i == start || (s.b[start] == '0' && s.i-start > 1) {
		return 0, errSyntax
	}
	return n, nil
}

func isNumChar(c byte) bool {
	return (c >= '0' && c <= '9') || c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E'
}

// skip pula um valor JSON qualquer, conferindo a estrutura.
func (s *scanner) skip(depth int) error {
	if depth > 200 {
		return errSyntax
	}
	switch c := s.peek(); {
	case c == '"':
		_, err := s.str()
		return err
	case c == '{':
		s.i++
		if s.eat('}') {
			return nil
		}
		for {
			if _, err := s.str(); err != nil {
				return err
			}
			if !s.eat(':') {
				return errSyntax
			}
			if err := s.skip(depth + 1); err != nil {
				return err
			}
			if s.eat('}') {
				return nil
			}
			if !s.eat(',') {
				return errSyntax
			}
		}
	case c == '[':
		s.i++
		if s.eat(']') {
			return nil
		}
		for {
			if err := s.skip(depth + 1); err != nil {
				return err
			}
			if s.eat(']') {
				return nil
			}
			if !s.eat(',') {
				return errSyntax
			}
		}
	case c == '-' || (c >= '0' && c <= '9'):
		for s.i < len(s.b) && isNumChar(s.b[s.i]) {
			s.i++
		}
		return nil
	default:
		for _, lit := range []string{"true", "false", "null"} {
			if strings.HasPrefix(string(s.b[s.i:min(s.i+5, len(s.b))]), lit) {
				s.i += len(lit)
				return nil
			}
		}
		return errSyntax
	}
}

func Parse(line []byte) (Record, error) {
	var r Record
	s := &scanner{b: line}
	if !s.eat('{') {
		return r, errSyntax
	}
	if s.eat('}') {
		return r, nil
	}
	for {
		key, err := s.str()
		if err != nil {
			return r, err
		}
		if !s.eat(':') {
			return r, errSyntax
		}
		var dst *string
		switch key {
		case "seq":
			if r.Seq, err = s.uint(); err != nil {
				return r, err
			}
		case "data":
			s.ws()
			start := s.i
			if err := s.skip(0); err != nil {
				return r, err
			}
			r.Data = append([]byte{}, line[start:s.i]...)
		case "ts":
			dst = &r.Ts
		case "host":
			dst = &r.Host
		case "kind":
			dst = &r.Kind
		case "level":
			dst = &r.Level
		case "user":
			dst = &r.User
		case "msg":
			dst = &r.Msg
		case "prev":
			dst = &r.Prev
		case "hash":
			dst = &r.Hash
		default:
			if err := s.skip(0); err != nil {
				return r, err
			}
		}
		if dst != nil {
			if *dst, err = s.str(); err != nil {
				return r, err
			}
		}
		if s.eat('}') {
			break
		}
		if !s.eat(',') {
			return r, errSyntax
		}
	}
	if s.peek() != 0 {
		return r, errSyntax
	}
	return r, nil
}

// topLevelUint procura uma chave no primeiro nível de um objeto JSON e lê seu valor inteiro.
func topLevelUint(obj []byte, want string) (uint64, bool) {
	s := &scanner{b: obj}
	if !s.eat('{') || s.eat('}') {
		return 0, false
	}
	for {
		key, err := s.str()
		if err != nil || !s.eat(':') {
			return 0, false
		}
		if key == want {
			if c := s.peek(); c < '0' || c > '9' {
				return 0, false
			}
			n, err := s.uint()
			return n, err == nil
		}
		if s.skip(0) != nil || !s.eat(',') {
			return 0, false
		}
	}
}
