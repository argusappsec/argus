package cmd

import "testing"

func TestNormalizePersonaName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"strips leading @ and whitespace", "  @Ercole ", "Ercole"},
		{"plain single word", "Ercole", "Ercole"},
		{"empty is valid (brand default)", "  ", ""},
		{"multi-word kept (vocative form)", "Ercole di Tebe", "Ercole di Tebe"},
		{"multi-word with @ stripped", "@Ercole di Tebe", "Ercole di Tebe"},
		{"internal whitespace collapsed", " Ercole   di  Tebe ", "Ercole di Tebe"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizePersonaName(tt.in); got != tt.want {
				t.Errorf("normalizePersonaName(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
