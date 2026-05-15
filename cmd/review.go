package cmd

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/redcarbon-dev/argus/pkg/agent"
	"github.com/redcarbon-dev/argus/pkg/codehost/github"
	"github.com/redcarbon-dev/argus/pkg/memory"
	"github.com/redcarbon-dev/argus/pkg/report"
)

// reviewCmd is the non-interactive entry point. It clones the target repo,
// seeds the agent with a "Please review …" prompt and exits when
// finalize_report is called. Shares the runtime (provider, registry, soul,
// audit, conversation) with `argus chat` via buildRuntime — the only
// review-specific code is the clone, the report writer, and the post-run
// memory curation.
func reviewCmd() *cobra.Command {
	var (
		model    string
		ref      string
		maxTurns int
		homeDir  string
	)
	c := &cobra.Command{
		Use:   "review <github-url>",
		Short: "Run a non-interactive security review on a GitHub repository.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Minute)
			defer cancel()

			rt, err := buildRuntime(ctx, runtimeOptions{HomeOverride: homeDir, Model: model})
			if err != nil {
				return err
			}
			defer rt.Close()

			u, err := github.ParseURL(args[0])
			if err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "→ resolving %s@%s\n", u.FullName, defaultIfEmpty(ref, "HEAD"))
			co, err := rt.Cloner.Clone(ctx, u, ref)
			if err != nil {
				return fmt.Errorf("clone: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "→ checkout ready at %s (sha=%s)\n", co.Path, co.SHA)

			rt.Session.SetRoot(co.Path)

			rw := report.NewWriter(filepath.Join(rt.Home, "reports"))

			ag := agent.New(agent.Options{
				Provider:     rt.Provider,
				Audit:        rt.Audit,
				Reports:      rw,
				Tools:        rt.Registry,
				Conversation: rt.Conversation,
				Soul:         rt.Soul,
				MaxTurns:     maxTurns,
			})

			fmt.Fprintln(cmd.OutOrStdout(), "→ running agent loop")
			rep, err := ag.Run(ctx, agent.Target{
				Repo: u.FullName,
				SHA:  co.SHA,
				Path: co.Path,
			})
			if err != nil {
				return fmt.Errorf("agent: %w", err)
			}

			reportPath := filepath.Join(rt.Home, "reports", reportSlug(u.FullName), co.SHA+".md")
			fmt.Fprintf(cmd.OutOrStdout(), "✓ review complete: %d findings — %s\n", len(rep.Findings), reportPath)
			fmt.Fprintf(cmd.OutOrStdout(), "  conversation log: %s\n", rt.ConvoPath)

			// Curate memory on successful completion. Failure is non-fatal —
			// the report is the user-facing product; memory is hygiene.
			fmt.Fprintln(cmd.OutOrStdout(), "→ curating memory")
			if err := memory.Curate(ctx, memory.Options{
				ConversationPath: rt.ConvoPath,
				MemoryPath:       filepath.Join(rt.Home, "MEMORY.md"),
				Provider:         rt.Provider,
			}); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "  warning: memory curation failed: %v\n", err)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "  memory: %s\n", filepath.Join(rt.Home, "MEMORY.md"))
			}
			return nil
		},
	}
	c.Flags().StringVar(&model, "model", "", "Override the default model from argus.yaml (e.g. gemini-2.5-pro)")
	c.Flags().StringVar(&ref, "ref", "", "Branch, tag, or commit SHA to review (default: remote HEAD)")
	c.Flags().IntVar(&maxTurns, "max-turns", 50, "Safety-net cap on agent loop turns")
	c.Flags().StringVar(&homeDir, "home", "", "Override ~/.argus home directory")
	return c
}

// resolveHome and friends are shared with runtime.go.
func reportSlug(full string) string {
	out := make([]rune, 0, len(full))
	for _, r := range full {
		switch r {
		case '/', '\\', ':', ' ':
			out = append(out, '_')
		default:
			out = append(out, r)
		}
	}
	return string(out)
}

func defaultIfEmpty(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
