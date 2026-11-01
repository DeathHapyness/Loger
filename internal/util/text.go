package util

import "strings"

// JoinArgv junta argv num texto legível, com aspas onde precisa.
func JoinArgv(argv []string) string {
	parts := make([]string, len(argv))
	for i, a := range argv {
		switch {
		case a == "":
			parts[i] = "''"
		case strings.ContainsFunc(a, needsQuote):
			parts[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		default:
			parts[i] = a
		}
	}
	return strings.Join(parts, " ")
}

func needsQuote(c rune) bool {
	return isSpace(c) || strings.ContainsRune("'\"$`\\|&;<>(){}*?", c)
}

// isSpace segue char::is_whitespace do Rust, para o texto sair igual ao da versão antiga.
func isSpace(c rune) bool {
	switch c {
	case ' ', '\t', '\n', '\v', '\f', '\r', 0x85, 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000:
		return true
	}
	return c >= 0x2000 && c <= 0x200a
}

func Basename(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}
