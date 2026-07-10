package cli

import (
	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/gitattr"
)

func newTrackCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "track <pattern>",
		Short: "Track a file pattern for git-vault encryption",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return gitattr.Track(".gitattributes", args[0])
		},
	}
}
