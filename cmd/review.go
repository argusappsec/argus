package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/redcarbon-dev/argus/pkg/agent"
	"github.com/redcarbon-dev/argus/pkg/audit"
	"github.com/redcarbon-dev/argus/pkg/conversation"
	"github.com/redcarbon-dev/argus/pkg/codehost/github"
	"github.com/redcarbon-dev/argus/pkg/provider/gemini"
	"github.com/redcarbon-dev/argus/pkg/report"
	"github.com/redcarbon-dev/argus/pkg/security"
	"github.com/redcarbon-dev/argus/pkg/session"
	"github.com/redcarbon-dev/argus/pkg/soul"
	"github.com/redcarbon-dev/argus/pkg/tool"
)

func reviewCmd() *cobra.Command {
	var (
		model    string
		ref      string
		maxTurns int
		homeDir  string
	)
	c := &cobra.Command{
		Use:   "review <github-url>",
		Short: "Run a white-box security review on a GitHub repository.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			home, err := resolveHome(homeDir)
			if err != nil {
				return err
			}

			apiKey := os.Getenv("GEMINI_API_KEY")
			if apiKey == "" {
				return fmt.Errorf("GEMINI_API_KEY is required (export it or place it in %s/.env)", home)
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Minute)
			defer cancel()

			u, err := github.ParseURL(args[0])
			if err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "→ resolving %s@%s\n", u.FullName, defaultIfEmpty(ref, "HEAD"))
			cloner := github.NewCloner(filepath.Join(home, "cache"))
			co, err := cloner.Clone(ctx, u, ref)
			if err != nil {
				return fmt.Errorf("clone: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "→ checkout ready at %s (sha=%s)\n", co.Path, co.SHA)

			aud, err := audit.NewLogger(filepath.Join(home, "audit.log.jsonl"))
			if err != nil {
				return err
			}
			defer aud.Close()

			sess := session.New()
			sess.SetRoot(co.Path)

			convoPath := filepath.Join(home, "conversations", sess.ID()+".jsonl")
			convoWriter, err := conversation.NewWriter(convoPath, sess.ID())
			if err != nil {
				return err
			}
			defer convoWriter.Close()

			soulPath := filepath.Join(home, "SOUL.md")
			s, err := soul.Load(soulPath)
			if err != nil {
				return fmt.Errorf("load soul: %w", err)
			}

			contextDir := filepath.Join(home, "context")

			reg := tool.NewRegistry()
			reg.Register(tool.NewListFiles(sess))
			reg.Register(tool.NewReadFile(sess))
			reg.Register(tool.NewGrep(sess))
			reg.Register(tool.NewListContext(contextDir))
			reg.Register(tool.NewReadContext(contextDir))
			reg.Register(tool.NewStartReviewLocal(sess))
			reg.Register(tool.NewStartReviewGitHub(sess, cloner))
			reg.Register(security.NewSemgrep(sess, security.ExecRunner{}))
			reg.Register(security.NewGitleaks(sess, security.ExecRunner{}))

			rw := report.NewWriter(filepath.Join(home, "reports"))

			prov, err := gemini.New(ctx, apiKey, model)
			if err != nil {
				return err
			}

			ag := agent.New(agent.Options{
				Provider:     prov,
				Audit:        aud,
				Reports:      rw,
				Tools:        reg,
				Conversation: convoWriter,
				Soul:         s,
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

			reportPath := filepath.Join(home, "reports", reportSlug(u.FullName), co.SHA+".md")
			fmt.Fprintf(cmd.OutOrStdout(), "✓ review complete: %d findings — %s\n", len(rep.Findings), reportPath)
			fmt.Fprintf(cmd.OutOrStdout(), "  conversation log: %s\n", convoPath)
			return nil
		},
	}
	c.Flags().StringVar(&model, "model", "gemini-2.5-flash", "Gemini model id")
	c.Flags().StringVar(&ref, "ref", "", "Branch, tag, or commit SHA to review (default: remote HEAD)")
	c.Flags().IntVar(&maxTurns, "max-turns", 50, "Safety-net cap on agent loop turns")
	c.Flags().StringVar(&homeDir, "home", "", "Override ~/.argus home directory")
	return c
}

func resolveHome(override string) (string, error) {
	if override != "" {
		if err := os.MkdirAll(override, 0o700); err != nil {
			return "", fmt.Errorf("create home: %w", err)
		}
		return override, nil
	}
	if env := os.Getenv("ARGUS_HOME"); env != "" {
		if err := os.MkdirAll(env, 0o700); err != nil {
			return "", fmt.Errorf("create home: %w", err)
		}
		return env, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home dir: %w", err)
	}
	dir := filepath.Join(home, ".argus")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create home: %w", err)
	}
	return dir, nil
}

func reportSlug(full string) string {
	// Mirror report.slugify (kept private there). Acceptable duplication for
	// the CLI; we only need it to print the expected path.
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
