package cmd

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/redcarbon-dev/argus/pkg/skill"
)

// skillCmd manages user-curated agent skills stored under ~/.argus/skills/.
//
// Authoring a skill is deliberately just "write a file": create
// ~/.argus/skills/<name>/SKILL.md with a name/description (+ optional tags)
// frontmatter and a markdown body, then invoke it in chat with /<name>.
func skillCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "skill",
		Short: "Manage agent skills (~/.argus/skills/<name>/SKILL.md)",
		Long: "Manage user-curated agent skills.\n\n" +
			"A skill is a directory ~/.argus/skills/<name>/SKILL.md with a YAML\n" +
			"frontmatter (name, description, optional tags) and a markdown body.\n" +
			"To add one, just create the file. To run it in chat, type /<name>.",
	}
	c.AddCommand(skillListCmd())
	c.AddCommand(skillRemoveCmd())
	return c
}

func skillListCmd() *cobra.Command {
	var homeDir string
	c := &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "List available skills",
		RunE: func(cmd *cobra.Command, args []string) error {
			home, err := resolveHome(homeDir)
			if err != nil {
				return err
			}
			dir := filepath.Join(home, "skills")
			cat := skill.NewCatalog(skill.Builtin(), dir)
			entries, errs := cat.ListEntries()
			for _, e := range errs {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: %v\n", e)
			}
			if len(entries) == 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "No skills found.\n")
				fmt.Fprintf(cmd.OutOrStdout(), "Add one by creating %s/<name>/SKILL.md\n", dir)
				return nil
			}
			sort.Slice(entries, func(i, j int) bool { return entries[i].Skill.Name < entries[j].Skill.Name })
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tSOURCE\tDESCRIPTION\tTAGS")
			for _, e := range entries {
				s := e.Skill
				desc := s.Description
				if len(desc) > 60 {
					desc = desc[:57] + "..."
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", s.Name, e.Source, desc, strings.Join(s.Tags, ", "))
			}
			return w.Flush()
		},
	}
	c.Flags().StringVar(&homeDir, "home", "", "Override ~/.argus home directory")
	return c
}

func skillRemoveCmd() *cobra.Command {
	var homeDir string
	c := &cobra.Command{
		Use:     "rm <name>",
		Aliases: []string{"remove"},
		Short:   "Remove a skill",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			home, err := resolveHome(homeDir)
			if err != nil {
				return err
			}
			dir := filepath.Join(home, "skills")
			name := args[0]
			cat := skill.NewCatalog(skill.Builtin(), dir)
			user, builtin, err := cat.Locate(name)
			if err != nil {
				return fmt.Errorf("remove skill %q: %w", name, err)
			}
			out := cmd.OutOrStdout()
			switch {
			case !user && !builtin:
				fmt.Fprintf(out, "No skill named %q found.\n", name)
			case !user && builtin:
				// Pure built-in: nothing on disk to remove. Say so plainly rather
				// than printing a misleading "Removed".
				fmt.Fprintf(out, "Skill %q is built-in: it lives in the binary and cannot be removed.\n", name)
			case user && builtin:
				// Override: delete the user copy; the built-in resurfaces.
				if err := skill.Delete(dir, name); err != nil {
					return fmt.Errorf("remove skill %q: %w", name, err)
				}
				fmt.Fprintf(out, "Removed your override of %q; the built-in skill is active again.\n", name)
			default: // user && !builtin: user-only, today's behaviour
				if err := skill.Delete(dir, name); err != nil {
					return fmt.Errorf("remove skill %q: %w", name, err)
				}
				fmt.Fprintf(out, "Removed skill %q\n", name)
			}
			return nil
		},
	}
	c.Flags().StringVar(&homeDir, "home", "", "Override ~/.argus home directory")
	return c
}
