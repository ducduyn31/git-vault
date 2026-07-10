package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newTrackCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "track <pattern>",
		Short: "Track a file pattern for git-vault encryption",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("git vault track: not implemented in scaffold")
		},
	}
}
