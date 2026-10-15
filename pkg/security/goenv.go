package security

import "path/filepath"

// goProxy is the only module source a Go-driving Tool may download from: the
// public Go module proxy, with no `direct` fallback, so the go command never
// fetches from a VCS host a go.mod in the checkout names (ADR 0027). Downloads
// are verified against the checksum database (goSumDB).
const (
	goProxy = "https://proxy.golang.org"
	goSumDB = "sum.golang.org"
)

// goBinary is the go command, which every Tool that loads the reviewed
// packages through it (gosec, govulncheck) requires next to its own binary.
var goBinary = Binary{Name: "go", InstallHint: "brew install go  (or see https://go.dev/doc/install)"}

// goEnv is the hardened Go profile every Tool that drives the go command over
// the code under review (gosec, govulncheck, osv-scanner's Go call analysis)
// runs with, on top of the scratch allow-list (ADR 0027). The go command's
// defaults are written for a developer building their own code; over a
// stranger's checkout each of them is a door:
//
//   - GOTOOLCHAIN=local: a go.mod asking for a newer Go fails instead of
//     downloading and running that toolchain.
//   - GOFLAGS=-mod=readonly: go.mod and go.sum are never rewritten.
//   - GOWORK=off: a go.work above the target cannot pull other modules in.
//   - CGO_ENABLED=0: no C compiler runs on the checkout's cgo directives.
//   - GOPROXY, GOSUMDB: modules come from the proxy only, checksum-verified.
//   - GOENV=off: no go env file (the daemon user's or anyone's) changes any
//     of the above.
//   - GOPACKAGESDRIVER=off: go/packages, which these Tools load code through,
//     otherwise runs any gopackagesdriver binary it finds on PATH.
//   - GOPATH, GOCACHE: the module and build caches live in the scratch
//     directory, so nothing persists into the next run.
//
// No variable here carries a credential, so nothing a Tool learns can be used
// against a private module host either.
func (s *scratch) goEnv() []string {
	return []string{
		"GOTOOLCHAIN=local",
		"GOFLAGS=-mod=readonly",
		"GOWORK=off",
		"CGO_ENABLED=0",
		"GOPROXY=" + goProxy,
		"GOSUMDB=" + goSumDB,
		"GOENV=off",
		"GOPACKAGESDRIVER=off",
		"GOPATH=" + filepath.Join(s.home(), "go"),
		"GOCACHE=" + filepath.Join(s.home(), ".cache", "go-build"),
	}
}
