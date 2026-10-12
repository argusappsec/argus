// Package security wraps external static-analysis binaries (semgrep, gitleaks,
// and future tools) as agent Tools.
//
// Each tool follows the same pattern:
//   - take a *session.Session at construction so the target directory tracks
//     the current review, and accept a caller-supplied `path` for a scan that
//     belongs to no review (see target.go),
//   - take an injectable Runner so unit tests can stub out the external binary,
//   - run the binary from a per-run scratch directory, never the checkout,
//     with an explicit environment allow-list (scratch.go),
//   - pass the binary's "ignore repository config" flags and hand it
//     Argus's own config, so nothing committed in the checkout changes what
//     it does (ADR 0027),
//   - shell out to the binary with structured JSON output written to a
//     report file,
//   - parse that report into a Report (report.go), marking the findings the
//     code under review tries to suppress as suppressed_in_repo (checkout.go
//     reads the marker), and return it as JSON to the agent.
//
// New security tools live in their own file inside this package (semgrep.go,
// gitleaks.go, ...). The shared infrastructure (Runner, ExecRunner) is in
// exec.go.
package security
