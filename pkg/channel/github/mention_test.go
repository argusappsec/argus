package github

import (
	"reflect"
	"testing"
)

func TestParseMention(t *testing.T) {
	cases := []struct {
		name        string
		persona     string // operator-configured persona name ("" = brand only)
		body        string
		wantOK      bool
		wantRequest string
	}{
		// Vocative: the bare brand name opening the comment is the canonical
		// form (@argus on github.com belongs to an unrelated real user).
		{"vocative", "", "argus explain this", true, "explain this"},
		{"vocative capitalised", "", "Argus mi vedi questa cosa", true, "mi vedi questa cosa"},
		{"vocative with comma", "", "Argus, ignore this finding", true, "ignore this finding"},
		{"vocative with colon", "", "argus: check this finding", true, "check this finding"},
		{"bare vocative", "", "Argus", true, ""},
		// Opening position only: a name mid-sentence talks ABOUT Argus, not TO it.
		{"vocative mid-sentence is not a request", "", "I think argus is wrong here", false, ""},
		{"vocative substring is not a request", "", "Arguses are mythical beasts", false, ""},
		{"possessive is not a vocative", "", "argus's finding looks wrong", false, ""},

		// Brand @-handle: kept as an alias, matched anywhere in the body.
		{"plain mention", "", "@argus explain this", true, "explain this"},
		{"mention mid-sentence", "", "hey @argus what is this", true, "hey what is this"},
		{"trailing punctuation", "", "@argus, ignore this finding", true, "ignore this finding"},
		{"case insensitive", "", "@Argus explain", true, "explain"},
		{"bare mention", "", "@argus", true, ""},
		{"no mention", "", "looks good, merging", false, ""},
		{"substring is not a mention", "", "email me at me@argusmail.com", false, ""},
		{"empty body", "", "", false, ""},
		// A persona name is set but the comment addresses only the brand:
		// both brand forms are always accepted.
		{"brand handle still works with persona set", "Ercole", "@argus explain this", true, "explain this"},
		{"brand vocative still works with persona set", "Ercole", "Argus, explain this", true, "explain this"},

		// Persona forms: the custom name is accepted alongside the brand.
		{"persona mention", "Ercole", "@Ercole explain this", true, "explain this"},
		{"persona case insensitive", "Ercole", "@ercole explain this", true, "explain this"},
		{"persona trailing punctuation", "Ercole", "@ercole, explain this", true, "explain this"},
		{"persona mid-sentence", "Ercole", "hey @ercole what is this", true, "hey what is this"},
		{"persona bare mention", "Ercole", "@Ercole", true, ""},
		{"persona substring is not a mention", "Ercole", "ping @ercoleanni about it", false, ""},
		{"persona vocative", "Ercole", "Ercole explain this", true, "explain this"},
		{"persona vocative with comma", "Ercole", "ercole, explain this", true, "explain this"},
		{"persona vocative mid-sentence is not a request", "Ercole", "ask Ercole about it", false, ""},
		// Without the persona configured, its forms are just text.
		{"persona handle inert when unconfigured", "", "@ercole explain this", false, ""},
		{"persona vocative inert when unconfigured", "", "ercole explain this", false, ""},

		// The vocative is tried first; otherwise the FIRST accepted @-handle
		// is the one stripped when several appear.
		{"first token removed only", "Ercole", "@argus and @ercole look", true, "and @ercole look"},
		{"vocative wins over later handle", "Ercole", "Argus tell @ercole to look", true, "tell @ercole to look"},

		// Dedup: a persona literally named "argus" collapses into the brand
		// forms rather than doubling them.
		{"persona named argus dedups", "argus", "@argus explain this", true, "explain this"},
		{"persona named Argus dedups", "Argus", "Argus, explain this", true, "explain this"},

		// A multi-word persona name has no single @handle, but it works in
		// full as a vocative.
		{"multiword persona has no mention handle", "Ercole il Guardiano", "@Ercole explain", false, ""},
		{"multiword persona vocative", "Ercole il Guardiano", "Ercole il Guardiano, guarda qui", true, "guarda qui"},
		{"multiword persona vocative case insensitive", "Ercole il Guardiano", "ercole il guardiano guarda qui", true, "guarda qui"},
		{"multiword persona partial name is not a vocative", "Ercole il Guardiano", "Ercole, guarda qui", false, ""},
		{"multiword persona brand still works", "Ercole il Guardiano", "@argus explain", true, "explain"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, ok := newMentionMatcher(tc.persona).parse(tc.body)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && req != tc.wantRequest {
				t.Errorf("request = %q, want %q", req, tc.wantRequest)
			}
		})
	}
}

func TestNewMentionMatcher(t *testing.T) {
	cases := []struct {
		name      string
		persona   string
		tokens    []string
		vocatives [][]string
	}{
		{"brand only", "", []string{"@argus"}, [][]string{{"argus"}}},
		{"persona added", "Ercole", []string{"@argus", "@Ercole"}, [][]string{{"argus"}, {"Ercole"}}},
		{"whitespace trimmed", "  Ercole  ", []string{"@argus", "@Ercole"}, [][]string{{"argus"}, {"Ercole"}}},
		{"argus deduped", "argus", []string{"@argus"}, [][]string{{"argus"}}},
		{"Argus deduped case-insensitive", "Argus", []string{"@argus"}, [][]string{{"argus"}}},
		{"multiword yields vocative but no handle", "Ercole il Guardiano", []string{"@argus"}, [][]string{{"argus"}, {"Ercole", "il", "Guardiano"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newMentionMatcher(tc.persona)
			if !reflect.DeepEqual(m.tokens, tc.tokens) {
				t.Errorf("tokens = %v, want %v", m.tokens, tc.tokens)
			}
			if !reflect.DeepEqual(m.vocatives, tc.vocatives) {
				t.Errorf("vocatives = %v, want %v", m.vocatives, tc.vocatives)
			}
		})
	}
}
