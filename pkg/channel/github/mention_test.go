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
		// Brand handle: behavior with no persona configured (unchanged).
		{"plain mention", "", "@argus explain this", true, "explain this"},
		{"mention mid-sentence", "", "hey @argus what is this", true, "hey what is this"},
		{"trailing punctuation", "", "@argus, ignore this finding", true, "ignore this finding"},
		{"case insensitive", "", "@Argus explain", true, "explain"},
		{"bare mention", "", "@argus", true, ""},
		{"no mention", "", "looks good, merging", false, ""},
		{"substring is not a mention", "", "email me at me@argusmail.com", false, ""},
		{"empty body", "", "", false, ""},
		// A persona name is set but the comment addresses only the brand handle:
		// @argus is always accepted.
		{"brand still works with persona set", "Ercole", "@argus explain this", true, "explain this"},

		// Persona handle: the custom name is accepted alongside @argus.
		{"persona mention", "Ercole", "@Ercole explain this", true, "explain this"},
		{"persona case insensitive", "Ercole", "@ercole explain this", true, "explain this"},
		{"persona trailing punctuation", "Ercole", "@ercole, explain this", true, "explain this"},
		{"persona mid-sentence", "Ercole", "hey @ercole what is this", true, "hey what is this"},
		{"persona bare mention", "Ercole", "@Ercole", true, ""},
		{"persona substring is not a mention", "Ercole", "ping @ercoleanni about it", false, ""},
		// Without the persona configured, its handle is just text.
		{"persona handle inert when unconfigured", "", "@ercole explain this", false, ""},

		// Only the FIRST accepted token is stripped when several appear.
		{"first token removed only", "Ercole", "@argus and @ercole look", true, "and @ercole look"},

		// Dedup: a persona literally named "argus" collapses into the brand
		// handle rather than doubling it — @argus still matches once.
		{"persona named argus dedups", "argus", "@argus explain this", true, "explain this"},
		{"persona named Argus dedups", "Argus", "@Argus explain", true, "explain"},

		// A multi-word persona name has no single @handle: only @argus matches.
		{"multiword persona has no mention handle", "Ercole il Guardiano", "@Ercole explain", false, ""},
		{"multiword persona brand still works", "Ercole il Guardiano", "@argus explain", true, "explain"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, ok := parseMention(tc.body, mentionTokens(tc.persona))
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && req != tc.wantRequest {
				t.Errorf("request = %q, want %q", req, tc.wantRequest)
			}
		})
	}
}

func TestMentionTokens(t *testing.T) {
	cases := []struct {
		name    string
		persona string
		want    []string
	}{
		{"brand only", "", []string{"@argus"}},
		{"persona added", "Ercole", []string{"@argus", "@Ercole"}},
		{"whitespace trimmed", "  Ercole  ", []string{"@argus", "@Ercole"}},
		{"argus deduped", "argus", []string{"@argus"}},
		{"Argus deduped case-insensitive", "Argus", []string{"@argus"}},
		{"multiword yields no handle", "Ercole il Guardiano", []string{"@argus"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := mentionTokens(tc.persona); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("mentionTokens(%q) = %v, want %v", tc.persona, got, tc.want)
			}
		})
	}
}
