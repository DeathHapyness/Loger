package util

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

// SSHFingerprint calcula o fingerprint de uma chave pública no formato do sshd ("SHA256:abc...").
func SSHFingerprint(b64Key string) (string, bool) {
	raw, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		if raw, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(b64Key, "=")); err != nil {
			return "", false
		}
	}
	sum := sha256.Sum256(raw)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), true
}
