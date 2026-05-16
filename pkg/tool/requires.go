package tool

// Requirement declares one external CLI binary a Tool needs at runtime.
//
// Tools that shell out to external commands implement the Requirer interface
// to advertise their dependencies. argus doctor inspects the registry and
// asks each Requirer what binaries it needs, so there's a single source of
// truth: the tool that uses the binary also declares it.
type Requirement struct {
	Binary      string // command name as it appears on PATH (e.g. "semgrep")
	InstallHint string // human-friendly install command (e.g. "brew install semgrep")
}

// Requirer is the optional interface implemented by tools with external
// binary dependencies. Tools that don't shell out (list_files, read_file,
// grep, ...) simply don't implement it.
type Requirer interface {
	Requires() []Requirement
}
