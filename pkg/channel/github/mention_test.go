package github

import "testing"

func TestParseMention(t *testing.T) {
	cases := []struct {
		name        string
		body        string
		wantOK      bool
		wantRequest string
	}{
		{"plain mention", "@argus explain this", true, "explain this"},
		{"mention mid-sentence", "hey @argus what is this", true, "hey what is this"},
		{"trailing punctuation", "@argus, ignore this finding", true, "ignore this finding"},
		{"case insensitive", "@Argus explain", true, "explain"},
		{"bare mention", "@argus", true, ""},
		{"no mention", "looks good, merging", false, ""},
		{"substring is not a mention", "email me at me@argusmail.com", false, ""},
		{"empty body", "", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, ok := parseMention(tc.body)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && req != tc.wantRequest {
				t.Errorf("request = %q, want %q", req, tc.wantRequest)
			}
		})
	}
}
