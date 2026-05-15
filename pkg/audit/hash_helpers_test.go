package audit_test

import (
	"crypto/sha256"
	"encoding/hex"
)

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

func hexEncode(b []byte) string {
	return hex.EncodeToString(b)
}
