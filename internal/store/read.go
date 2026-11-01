package store

import (
	"bufio"
	"bytes"
	"io"
	"os"
)

const maxLine = 16 << 20

// EachLine chama fn para cada linha não vazia do arquivo, em ordem. Se fn devolver
// false, a leitura para.
func EachLine(path string, fn func(n int, line []byte) bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), maxLine)
	n := 0
	for sc.Scan() {
		n++
		if len(sc.Bytes()) > 0 && !fn(n, sc.Bytes()) {
			return nil
		}
	}
	return sc.Err()
}

// EachLineReverse lê o arquivo do fim para o começo, sem carregá-lo inteiro.
func EachLineReverse(path string, fn func(line []byte) bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	const chunk = 64 * 1024
	pos := st.Size()
	var tail []byte
	buf := make([]byte, chunk)
	for pos > 0 {
		n := int64(chunk)
		if pos < n {
			n = pos
		}
		pos -= n
		if _, err := f.ReadAt(buf[:n], pos); err != nil && err != io.EOF {
			return err
		}
		data := append(append([]byte{}, buf[:n]...), tail...)
		i := bytes.LastIndexByte(data, '\n')
		for i >= 0 {
			if line := data[i+1:]; len(line) > 0 && !fn(line) {
				return nil
			}
			data = data[:i]
			i = bytes.LastIndexByte(data, '\n')
		}
		if len(data) > maxLine {
			return bufio.ErrTooLong
		}
		tail = data
	}
	if len(tail) > 0 {
		fn(tail)
	}
	return nil
}
