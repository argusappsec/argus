package github

import "strings"

// brandName is the bare name that always addresses Argus (ADR 0008). It is the
// brand and the universal fallback: even an instance the operator renamed
// still answers to it.
//
// A comment addresses the instance in one of two forms:
//
//   - the vocative — the bare name opening the comment ("Argus, look at
//     this"). This is the canonical, documented form: @argus on github.com
//     belongs to an unrelated real user, so the @-form on a public repo pings
//     a stranger.
//   - an @-handle anywhere in the body ("hey @argus what is this"), kept as an
//     accepted alias: people type it out of habit, and a bot that ignores its
//     own tag is worse UX than the spurious ping (which happens regardless of
//     what Argus accepts).
//
// The channel parses both forms itself rather than relying on GitHub's native
// mention resolution — a comment carrying neither is simply not addressed to
// Argus and is silently ignored.
const brandName = "argus"

// brandMentionToken is the @-handle alias of brandName.
const brandMentionToken = "@" + brandName

// mentionMatcher recognises the forms a comment may use to address this
// instance, computed once from the configured persona name. Matching stays
// pure Go — no LLM is consulted to decide whether a comment is addressed to
// Argus.
//
// Vocatives are matched only in opening position: a name in the middle of a
// sentence is a comment *about* Argus ("I think argus is wrong here"), not a
// request *to* it.
type mentionMatcher struct {
	tokens    []string   // @-handles, matched anywhere in the body
	vocatives [][]string // bare-name word sequences, matched at the start only
}

// newMentionMatcher builds the matcher: the brand (always, in both forms) plus
// the operator-configured persona name.
//
// Two edge cases shape the persona forms:
//   - An @-handle is a single whitespace-delimited word, so a multi-word
//     persona name ("Ercole il Guardiano") contributes no @token — but it
//     works fine as a vocative, so it is matched there in full.
//   - A persona name that is "argus" in any case is the brand already, so it
//     is deduped rather than added twice.
func newMentionMatcher(personaName string) mentionMatcher {
	m := mentionMatcher{
		tokens:    []string{brandMentionToken},
		vocatives: [][]string{{brandName}},
	}
	words := strings.Fields(personaName)
	if len(words) == 0 {
		return m
	}
	if len(words) == 1 {
		if strings.EqualFold(words[0], brandName) {
			return m
		}
		m.tokens = append(m.tokens, "@"+words[0])
	}
	m.vocatives = append(m.vocatives, words)
	return m
}

// parse reports whether body addresses this instance and returns the request
// with the matched form removed and surrounding whitespace collapsed (the text
// the agent acts on). Matching is case-insensitive and tolerates trailing
// punctuation after the name ("Argus, explain this" / "@ercole, explain this").
//
// The vocative is tried first; otherwise the body is scanned for an @-handle
// and the FIRST one found is stripped, matching the historical "first mention
// token removed" semantics. A body carrying no accepted form returns ok=false
// and the channel ignores it without replying (ADR 0008).
func (m mentionMatcher) parse(body string) (request string, ok bool) {
	fields := strings.Fields(body)
	if n := m.vocativeLen(fields); n > 0 {
		return strings.Join(fields[n:], " "), true
	}
	idx := -1
	for i, f := range fields {
		// Tolerate trailing punctuation ("@argus, explain this").
		if matchesToken(strings.TrimRight(f, ",.:;!?"), m.tokens) {
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

// vocativeLen returns how many leading fields of the comment spell one of the
// accepted bare names — the longest match when several apply, so a persona
// named "argus guardian" wins over the brand "argus" — or 0 when the comment
// does not open with a vocative.
func (m mentionMatcher) vocativeLen(fields []string) int {
	longest := 0
	for _, name := range m.vocatives {
		if len(name) > longest && opensWithName(fields, name) {
			longest = len(name)
		}
	}
	return longest
}

// opensWithName reports whether the comment's leading fields spell name,
// case-insensitive. Only the name's final word tolerates trailing punctuation:
// "Ercole, look" matches the name "Ercole", but "Ercole, il Guardiano" does
// not match "Ercole il Guardiano".
func opensWithName(fields, name []string) bool {
	if len(fields) < len(name) {
		return false
	}
	for i, w := range name {
		f := fields[i]
		if i == len(name)-1 {
			f = strings.TrimRight(f, ",.:;!?")
		}
		if !strings.EqualFold(f, w) {
			return false
		}
	}
	return true
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
