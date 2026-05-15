// Package security wraps external static-analysis binaries (semgrep, gitleaks,
// and future tools) as agent Tools.
//
// Each tool follows the same pattern:
//   - take a *session.Session at construction so the target directory tracks
//     the current review,
//   - take an injectable Runner so unit tests can stub out the external binary,
//   - shell out to the binary with structured JSON output,
//   - return the raw JSON string to the agent (the LLM is the consumer).
//
// New security tools live in their own file inside this package (semgrep.go,
// gitleaks.go, ...). The shared infrastructure (Runner, ExecRunner) is in
// exec.go.
package security
