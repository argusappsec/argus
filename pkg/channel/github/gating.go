package github

import "slices"

// Decision is the outcome of repo gating.
type Decision int

const (
	// Ignore means Argus does not act on the event.
	Ignore Decision = iota
	// Act means Argus proceeds with the review/acknowledgment.
	Act
)

// GatePolicy is the daemon-side policy that decides whether an installed repo
// is acted on (ADR 0008). It is pure and security-critical: trust is rooted
// in daemon-host ownership, never in the mere fact that the App was installed.
type GatePolicy struct {
	// AutoEnroll is the effective github.auto_enroll value. When true, any
	// repo the installation can access is acted on. When false, a repo must
	// additionally appear in EnabledRepos.
	AutoEnroll bool

	// InstallationRepos is the set of repos the App installation can access,
	// read from the GitHub API. A repo outside this set is never acted on.
	InstallationRepos []string

	// EnabledRepos is the explicit allow-list consulted only when AutoEnroll
	// is false (the "installed but not enabled" case).
	EnabledRepos []string
}

// Gate decides whether eventRepo (canonical "github.com/<owner>/<name>")
// should be acted on under the policy. The installation set is the outer
// bound; auto_enroll governs the inner decision.
func Gate(eventRepo string, p GatePolicy) Decision {
	if !slices.Contains(p.InstallationRepos, eventRepo) {
		return Ignore
	}
	if p.AutoEnroll {
		return Act
	}
	if slices.Contains(p.EnabledRepos, eventRepo) {
		return Act
	}
	return Ignore
}
