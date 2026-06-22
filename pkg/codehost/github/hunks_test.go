package github

import "testing"

func TestParseHunks(t *testing.T) {
	tests := []struct {
		name  string
		patch string
		want  []hunk
	}{
		{
			name:  "empty patch yields no hunks",
			patch: "",
			want:  nil,
		},
		{
			name:  "single hunk with explicit count",
			patch: "@@ -40,3 +40,5 @@ def load()\n-old\n+new1\n+new2",
			want:  []hunk{{40, 5}},
		},
		{
			name:  "bare new-start means one line",
			patch: "@@ -1 +1 @@\n-a\n+b",
			want:  []hunk{{1, 1}},
		},
		{
			name:  "multiple hunks in one patch",
			patch: "@@ -1,2 +1,3 @@\n+x\n@@ -10,0 +12,4 @@ ctx\n+y",
			want:  []hunk{{1, 3}, {12, 4}},
		},
		{
			name:  "lines that merely start with + are not hunk headers",
			patch: "+not a header\n@@ -5,1 +7,2 @@\n+z",
			want:  []hunk{{7, 2}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseHunks(tt.patch)
			if len(got) != len(tt.want) {
				t.Fatalf("hunks = %+v, want %+v", got, tt.want)
			}
			for i := range got {
				if got[i].NewStart != tt.want[i].start || got[i].NewLines != tt.want[i].lines {
					t.Errorf("hunk[%d] = {%d,%d}, want {%d,%d}", i,
						got[i].NewStart, got[i].NewLines, tt.want[i].start, tt.want[i].lines)
				}
			}
		})
	}
}

// hunk is a compact expectation pair for the table above.
type hunk struct{ start, lines int }
