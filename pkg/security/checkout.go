package security

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/argusappsec/argus/pkg/session"
)

// maxSourceRead caps how much of one file Argus reads to look for a
// suppression marker. Markers sit on the finding's own lines, which scanners
// only report in files they could parse.
const maxSourceRead = 16 << 20

// checkoutFiles is read access to the tree a scan ran over, for the one thing
// a scanner's report cannot say on its own: whether the code under review
// marks a finding as suppressed.
//
// Reads go through an os.Root, so a symlink the pull request committed cannot
// lead them outside the tree (ADR 0019). Only a yes or no about a marker comes
// out of it, never file content.
type checkoutFiles struct {
	base string // findings' paths are made relative to this
	root *os.Root
}

// openCheckout opens the tree a scan of target belongs to: the Session's
// checkout when a review pinned one, the target itself otherwise. A tree that
// cannot be opened yields a checkoutFiles that reads nothing, so findings are
// still reported, just without the marker.
func openCheckout(s *session.Session, target string) *checkoutFiles {
	base := s.Root()
	if base == "" || !within(base, target) {
		base = target
	}
	c := &checkoutFiles{base: base}
	if r, err := os.OpenRoot(base); err == nil {
		c.root = r
	}
	return c
}

func (c *checkoutFiles) close() {
	if c.root != nil {
		_ = c.root.Close()
	}
}

// rel turns a path a scanner reported into one relative to the checkout. It
// reports false, and returns the path unchanged, for a path outside it.
func (c *checkoutFiles) rel(path string) (string, bool) {
	if !filepath.IsAbs(path) {
		return filepath.ToSlash(filepath.Clean(path)), true
	}
	if !within(c.base, path) {
		return path, false
	}
	r, err := filepath.Rel(c.base, path)
	if err != nil {
		return path, false
	}
	return filepath.ToSlash(r), true
}

// read returns a file inside the checkout, by checkout-relative path.
func (c *checkoutFiles) read(rel string) ([]byte, bool) {
	if c.root == nil {
		return nil, false
	}
	f, err := c.root.Open(filepath.FromSlash(rel))
	if err != nil {
		return nil, false
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, maxSourceRead))
	if err != nil {
		return nil, false
	}
	return body, true
}

// list returns the names of the regular files directly inside a checkout
// directory, by checkout-relative path. A path that is not a directory lists
// nothing.
func (c *checkoutFiles) list(rel string) []string {
	if c.root == nil {
		return nil
	}
	if rel == "" {
		rel = "."
	}
	f, err := c.root.Open(filepath.FromSlash(rel))
	if err != nil {
		return nil
	}
	defer f.Close()
	entries, err := f.ReadDir(-1)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.Type().IsRegular() {
			out = append(out, e.Name())
		}
	}
	return out
}

// lines returns lines from..to (1-based, inclusive) of a checkout file, as
// many as exist.
func (c *checkoutFiles) lines(rel string, from, to int) []string {
	if from < 1 {
		from = 1
	}
	if c.root == nil || to < from {
		return nil
	}
	f, err := c.root.Open(filepath.FromSlash(rel))
	if err != nil {
		return nil
	}
	defer f.Close()
	sc := bufio.NewScanner(io.LimitReader(f, maxSourceRead))
	sc.Buffer(make([]byte, 0, 64<<10), maxSourceRead)
	var out []string
	for n := 1; n <= to && sc.Scan(); n++ {
		if n >= from {
			out = append(out, sc.Text())
		}
	}
	return out
}

// anyLine reports whether any of lines satisfies match.
func anyLine(lines []string, match func(string) bool) bool {
	for _, l := range lines {
		if match(l) {
			return true
		}
	}
	return false
}

// joinSlash joins checkout-relative path elements with forward slashes.
func joinSlash(elem ...string) string {
	return strings.TrimPrefix(filepath.ToSlash(filepath.Join(elem...)), "./")
}
