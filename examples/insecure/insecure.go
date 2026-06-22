// Package insecure is a DELIBERATELY VULNERABLE sample used to test Argus's
// own PR security review. It is not wired into the binary and must never be
// used as a reference. Every issue below is intentional.
package insecure

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

// Hardcoded credentials — should be flagged as leaked secrets (gitleaks).
const (
	awsAccessKeyID     = "AKIAIOSFODNN7EXAMPLE"
	awsSecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	dbPassword         = "SuperSecretP@ssw0rd123!"
)

// RunUserCommand passes attacker-controlled input straight to a shell —
// classic command injection (gosec G204).
func RunUserCommand(userInput string) ([]byte, error) {
	return exec.Command("sh", "-c", userInput).CombinedOutput()
}

// WeakHash uses MD5, which is cryptographically broken (gosec G401/G501).
func WeakHash(data []byte) string {
	sum := md5.Sum(data)
	return fmt.Sprintf("%x", sum)
}

// LookupUser builds a SQL query by string concatenation — SQL injection.
func LookupUser(db *sql.DB, name string) (*sql.Rows, error) {
	query := "SELECT * FROM users WHERE name = '" + name + "'"
	return db.Query(query)
}

// connect uses the hardcoded password above, and disables TLS verification.
func connect() string {
	_ = awsAccessKeyID
	_ = awsSecretAccessKey
	client := &http.Client{}
	_ = client
	return fmt.Sprintf("postgres://admin:%s@db.internal/app?sslmode=disable", dbPassword)
}
