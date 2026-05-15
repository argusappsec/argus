// Package config handles Argus's persistent configuration: secrets live in
// ~/.argus/.env (KEY=value, never commit), preferences will live in
// ~/.argus/argus.yaml in future versions.
//
// The .env loader is intentionally a minimal subset of dotenv:
//   - KEY=value
//   - KEY="value with spaces"
//   - # comments, blank lines
//
// No ${VAR} expansion, no `export ` prefix support. Just enough for storing
// API keys and tokens.
package config

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Env is a parsed .env file. It preserves the original line order and unknown
// content (comments, blank lines, keys we don't recognise) across Save so a
// human-edited file isn't trampled when Argus rewrites one key.
type Env struct {
	path  string
	lines []envLine // original-order representation
}

type envLine struct {
	// raw is the verbatim original line (comments, blanks). Used when this
	// line is NOT a key=value pair.
	raw string
	// key/value populated when raw represents an assignment.
	key, value string
	// isKV true when this line is a key=value assignment.
	isKV bool
}

// LoadEnv reads path, parsing key=value pairs. A missing file is not an
// error: the returned Env is empty and ready for Set+Save.
func LoadEnv(path string) (*Env, error) {
	e := &Env{path: path}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return e, nil
		}
		return nil, fmt.Errorf("config: open %s: %w", path, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		e.lines = append(e.lines, parseLine(line))
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	return e, nil
}

// EnvFromMap is a convenience for tests: an in-memory Env not bound to any
// path. Save() on such an Env returns an error.
func EnvFromMap(m map[string]string) *Env {
	e := &Env{}
	for k, v := range m {
		e.Set(k, v)
	}
	return e
}

// Get returns the value for key, or "" if absent.
func (e *Env) Get(key string) string {
	for i := len(e.lines) - 1; i >= 0; i-- { // last wins, mirroring shell semantics
		if e.lines[i].isKV && e.lines[i].key == key {
			return e.lines[i].value
		}
	}
	return ""
}

// Set adds or replaces a key. Insertion order is preserved on first write;
// subsequent updates rewrite the existing line.
func (e *Env) Set(key, value string) {
	for i := range e.lines {
		if e.lines[i].isKV && e.lines[i].key == key {
			e.lines[i].value = value
			return
		}
	}
	e.lines = append(e.lines, envLine{isKV: true, key: key, value: value})
}

// Save writes the Env back to its path, creating parent dirs as needed.
// Permissions are 0600 because the file carries secrets.
func (e *Env) Save() error {
	if e.path == "" {
		return errors.New("config: cannot save an in-memory Env (path is empty)")
	}
	if err := os.MkdirAll(filepath.Dir(e.path), 0o700); err != nil {
		return fmt.Errorf("config: mkdir: %w", err)
	}

	var b strings.Builder
	for _, ln := range e.lines {
		if !ln.isKV {
			b.WriteString(ln.raw)
			b.WriteByte('\n')
			continue
		}
		b.WriteString(ln.key)
		b.WriteByte('=')
		b.WriteString(quoteIfNeeded(ln.value))
		b.WriteByte('\n')
	}
	return os.WriteFile(e.path, []byte(b.String()), 0o600)
}

// ApplyToProcess writes each Env entry into os.Setenv UNLESS the key is
// already set to a non-empty value in the shell. Shell-exported values win
// (matches dotenv convention).
func (e *Env) ApplyToProcess() {
	for _, ln := range e.lines {
		if !ln.isKV {
			continue
		}
		if existing := os.Getenv(ln.key); existing != "" {
			continue
		}
		_ = os.Setenv(ln.key, ln.value)
	}
}

func parseLine(raw string) envLine {
	trim := strings.TrimSpace(raw)
	if trim == "" || strings.HasPrefix(trim, "#") {
		return envLine{raw: raw}
	}
	eq := strings.IndexByte(trim, '=')
	if eq <= 0 {
		return envLine{raw: raw}
	}
	key := strings.TrimSpace(trim[:eq])
	val := strings.TrimSpace(trim[eq+1:])
	// Strip matching surrounding quotes, preserving inner whitespace.
	if len(val) >= 2 {
		first, last := val[0], val[len(val)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			val = val[1 : len(val)-1]
		}
	}
	return envLine{raw: raw, key: key, value: val, isKV: true}
}

func quoteIfNeeded(v string) string {
	if strings.ContainsAny(v, " \t\"'#") || v == "" {
		// Escape internal double-quotes and backslashes, wrap in double quotes.
		v = strings.ReplaceAll(v, `\`, `\\`)
		v = strings.ReplaceAll(v, `"`, `\"`)
		return `"` + v + `"`
	}
	return v
}
