package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/gitattr"
	"github.com/ducduyn31/git-vault/internal/ui"
)

func newTrackCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "track <pattern>",
		Short: "Track a file pattern for git-vault encryption",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pattern := repoPath(args[0])
			if err := gitattr.Track(".gitattributes", pattern); err != nil {
				return err
			}
			ui.New(cmd.OutOrStdout()).Info(fmt.Sprintf("Tracking %s", pattern))
			return nil
		},
	}
}
