package github

import "testing"

func TestGate(t *testing.T) {
	const repo = "github.com/redcarbon-dev/argus"
	installed := []string{"github.com/redcarbon-dev/argus", "github.com/redcarbon-dev/other"}

	cases := []struct {
		name      string
		eventRepo string
		policy    GatePolicy
		want      Decision
	}{
		{
			name:      "auto_enroll acts on any installed repo",
			eventRepo: repo,
			policy:    GatePolicy{AutoEnroll: true, InstallationRepos: installed},
			want:      Act,
		},
		{
			name:      "repo outside installation is ignored even with auto_enroll",
			eventRepo: "github.com/someone/else",
			policy:    GatePolicy{AutoEnroll: true, InstallationRepos: installed},
			want:      Ignore,
		},
		{
			name:      "auto_enroll false ignores an installed-but-not-enabled repo",
			eventRepo: repo,
			policy:    GatePolicy{AutoEnroll: false, InstallationRepos: installed, EnabledRepos: nil},
			want:      Ignore,
		},
		{
			name:      "auto_enroll false acts on an explicitly enabled repo",
			eventRepo: repo,
			policy:    GatePolicy{AutoEnroll: false, InstallationRepos: installed, EnabledRepos: []string{repo}},
			want:      Act,
		},
		{
			name:      "auto_enroll false: enabled but not installed is still ignored",
			eventRepo: "github.com/someone/else",
			policy:    GatePolicy{AutoEnroll: false, InstallationRepos: installed, EnabledRepos: []string{"github.com/someone/else"}},
			want:      Ignore,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Gate(tc.eventRepo, tc.policy); got != tc.want {
				t.Errorf("Gate = %v, want %v", got, tc.want)
			}
		})
	}
}
