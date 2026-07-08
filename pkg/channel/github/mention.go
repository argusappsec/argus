package github

import "strings"

// brandMentionToken is the literal handle that always turns a PR comment into a
// request to Argus (ADR 0008). It is the brand and the universal fallback: even
// an instance the operator renamed still answers to @argus. The channel parses
// the token itself rather than relying on GitHub's native mention resolution —
// a comment carrying none of the accepted tokens is simply not addressed to
// Argus and is silently ignored.
const brandMentionToken = "@argus"

// mentionTokens returns the set of @-handles that address this instance: the
// brand @argus (always) plus @<persona> when the operator configured a persona
// name. Matching against these stays pure Go — no LLM is consulted to decide
// whether a comment is addressed to Argus.
//
// Two edge cases shape the persona token:
//   - A mention is a single whitespace-delimited word, so a multi-word persona
//     name ("Ercole il Guardiano") has no sensible single @handle; it is used
//     only in the system prompt and contributes no mention token here.
//   - A persona name that is "argus" in any case is the brand handle already,
//     so it is deduped rather than added twice.
func mentionTokens(personaName string) []string {
	tokens := []string{brandMentionToken}
	name := strings.TrimSpace(personaName)
	if name == "" || len(strings.Fields(name)) != 1 {
		return tokens
	}
	token := "@" + name
	if strings.EqualFold(token, brandMentionToken) {
		return tokens
	}
	return append(tokens, token)
}

// parseMention reports whether body addresses this instance — it carries one of
// the accepted mention tokens as a whitespace-delimited word — and returns the
// request with the FIRST matched token removed and surrounding whitespace
// collapsed (the text the agent acts on). Matching is case-insensitive and
// tolerates trailing punctuation ("@ercole, explain this"). When several
// accepted tokens appear, only the first is stripped, matching the historical
// "first mention token removed" semantics. A body carrying no accepted token
// returns ok=false and the channel ignores it without replying (ADR 0008).
func parseMention(body string, tokens []string) (request string, ok bool) {
	fields := strings.Fields(body)
	idx := -1
	for i, f := range fields {
		// Tolerate trailing punctuation ("@argus, explain this").
		if matchesToken(strings.TrimRight(f, ",.:;!?"), tokens) {
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

// matchesToken reports whether word equals any accepted token, case-insensitive.
func matchesToken(word string, tokens []string) bool {
	for _, t := range tokens {
		if strings.EqualFold(word, t) {
			return true
		}
	}
	return false
}
