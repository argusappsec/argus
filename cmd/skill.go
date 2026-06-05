package cmd

import (
	"fmt"
	"path/filepath"
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
			skills, errs := skill.LoadAll(dir)
			for _, e := range errs {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: %v\n", e)
			}
			if len(skills) == 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "No skills found in %s\n", dir)
				fmt.Fprintf(cmd.OutOrStdout(), "Add one by creating %s/<name>/SKILL.md\n", dir)
				return nil
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tDESCRIPTION\tTAGS")
			for _, s := range skills {
				desc := s.Description
				if len(desc) > 60 {
					desc = desc[:57] + "..."
				}
				fmt.Fprintf(w, "%s\t%s\t%s\n", s.Name, desc, strings.Join(s.Tags, ", "))
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
			name := args[0]
			if err := skill.Delete(filepath.Join(home, "skills"), name); err != nil {
				return fmt.Errorf("remove skill %q: %w", name, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Removed skill %q\n", name)
			return nil
		},
	}
	c.Flags().StringVar(&homeDir, "home", "", "Override ~/.argus home directory")
	return c
}
