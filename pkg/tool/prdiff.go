package tool

import (
	"context"
	"encoding/json"

	"github.com/redcarbon-dev/argus/pkg/session"
)

// NewPRDiff returns a `pr_diff` tool that exposes the pull request's changed
// files and patch hunks to the agent. The diff is pre-fetched by the channel
// from the GitHub API (pulls/{n}/files) and stashed on the Session; the agent
// uses it to judge PR-relevance (ADR 0009): report a finding only when it is on
// a changed line OR causally tied to the change, never the repo's pre-existing
// issues. Outside a PR review (e.g. `argus review`) no diff is set and the tool
// says so.
func NewPRDiff(s *session.Session) Tool {
	return &prDiff{sess: s}
}

type prDiff struct {
	sess *session.Session
}

func (t *prDiff) Name() string { return "pr_diff" }

func (t *prDiff) Description() string {
	return "Return the pull request's changed files and patch hunks (from the GitHub API). " +
		"Use this to judge which findings are relevant to THIS pull request: report an issue only " +
		"when it is on a changed line or is causally tied to the change (the diff calls an insecure " +
		"function defined elsewhere, bumps a dependency to a vulnerable version, etc.). Do NOT report " +
		"the repository's pre-existing issues that are unrelated to the change. " +
		"Returns an empty result when the current review is not a pull-request review."
}

func (t *prDiff) Schema() map[string]any {
	return map[string]any{
		"type":       "object",
		"properties": map[string]any{},
	}
}

func (t *prDiff) Execute(_ context.Context, _ map[string]any) (string, error) {
	diff, ok := t.sess.PRDiff()
	if !ok {
		return "No pull-request diff is available: this is not a pull-request review.", nil
	}

	type hunkOut struct {
		NewStart int `json:"new_start"`
		NewLines int `json:"new_lines"`
	}
	type fileOut struct {
		Path   string    `json:"path"`
		Status string    `json:"status"`
		Hunks  []hunkOut `json:"hunks"`
		Patch  string    `json:"patch,omitempty"`
	}
	out := struct {
		Files []fileOut `json:"files"`
	}{Files: make([]fileOut, 0, len(diff.Files))}

	for _, f := range diff.Files {
		fo := fileOut{Path: f.Path, Status: f.Status, Patch: f.Patch, Hunks: make([]hunkOut, 0, len(f.Hunks))}
		for _, h := range f.Hunks {
			fo.Hunks = append(fo.Hunks, hunkOut{NewStart: h.NewStart, NewLines: h.NewLines})
		}
		out.Files = append(out.Files, fo)
	}

	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
