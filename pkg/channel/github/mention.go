package github

import "strings"

// mentionToken is the literal handle that turns a PR comment into a request to
// Argus. The channel parses it itself rather than relying on GitHub's native
// mention resolution (ADR 0008): a comment without this token is simply not
// addressed to Argus and is silently ignored.
const mentionToken = "@argus"

// parseMention reports whether body addresses Argus (carries the @argus mention
// token as a whitespace-delimited word) and returns the request with the first
// mention token removed and surrounding whitespace collapsed — the text the
// agent should act on. A comment without the token returns ok=false and the
// channel ignores it without replying.
func parseMention(body string) (request string, ok bool) {
	fields := strings.Fields(body)
	idx := -1
	for i, f := range fields {
		// Tolerate trailing punctuation ("@argus, explain this").
		if strings.EqualFold(strings.TrimRight(f, ",.:;!?"), mentionToken) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return "", false
	}
	rest := make([]string, 0, len(fields)-1)
	rest = append(rest, fields[:idx]...)
	rest = append(rest, fields[idx+1:]...)
	return strings.Join(rest, " "), true
}
