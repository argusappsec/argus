package skill

import (
	"embed"
	"io/fs"
)

// builtinFS embeds the whole built-in skill tree — every SKILL.md and any
// supporting files a bundle carries (templates, examples). The `all:` prefix
// keeps files that would otherwise be ignored (e.g. those starting with "_"
// or "."), so a bundle's supporting material is never silently dropped.
//
//go:embed all:builtin
var builtinFS embed.FS

// Builtin returns the embedded built-in skill source, rebased so each skill is
// reachable at <name>/SKILL.md — the identical layout to the user directory
// (os.DirFS). This lets the Catalog treat both sources through one fs.FS path.
func Builtin() fs.FS {
	sub, err := fs.Sub(builtinFS, "builtin")
	if err != nil {
		// Impossible: the builtin directory is embedded at compile time, so the
		// subtree always exists. A panic here means a broken build, not a
		// recoverable runtime condition.
		panic("skill: rebase embedded builtin source: " + err.Error())
	}
	return sub
}
