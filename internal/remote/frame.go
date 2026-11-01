package remote

// Protocolo: TCP, quadros [u32 big-endian tamanho][nonce 24 bytes][dados cifrados].
// Cifra: XChaCha20-Poly1305 com chave compartilhada (gerada por "loger keygen"): quem não
// tem a chave não consegue ler, forjar nem alterar eventos.

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

const maxFrame = 1 << 20

var (
	errBadFrame = errors.New("quadro com tamanho inválido")
	errAuth     = errors.New("chave errada ou dados adulterados")
)

func ParseKey(s string) (cipher.AEAD, error) {
	k, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil || len(k) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("chave inválida: use `loger keygen` (64 caracteres hex)")
	}
	return chacha20poly1305.NewX(k)
}

func Keygen() string {
	k := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(k); err != nil {
		panic(err)
	}
	return hex.EncodeToString(k)
}

func writeFrame(w io.Writer, c cipher.AEAD, plain []byte) error {
	buf := make([]byte, 4+chacha20poly1305.NonceSizeX, 4+chacha20poly1305.NonceSizeX+len(plain)+c.Overhead())
	nonce := buf[4:]
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	buf = c.Seal(buf, nonce, plain, nil)
	binary.BigEndian.PutUint32(buf, uint32(len(buf)-4))
	_, err := w.Write(buf)
	return err
}

func readFrame(r io.Reader, c cipher.AEAD) ([]byte, error) {
	var l [4]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint32(l[:]))
	if n < chacha20poly1305.NonceSizeX || n > maxFrame {
		return nil, errBadFrame
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	plain, err := c.Open(nil, buf[:chacha20poly1305.NonceSizeX], buf[chacha20poly1305.NonceSizeX:], nil)
	if err != nil {
		return nil, errAuth
	}
	return plain, nil
}
