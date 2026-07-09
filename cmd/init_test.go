package cmd

import "testing"

func TestNormalizePersonaName(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"strips leading @ and whitespace", "  @Ercole ", "Ercole", false},
		{"plain single word", "Ercole", "Ercole", false},
		{"empty is valid (brand default)", "  ", "", false},
		{"multi-word rejected", "Ercole di Tebe", "", true},
		{"multi-word with @ rejected", "@Ercole di Tebe", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizePersonaName(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("normalizePersonaName(%q) = %q, want error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizePersonaName(%q): unexpected error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("normalizePersonaName(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
