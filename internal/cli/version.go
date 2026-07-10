package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version is the git-vault release version. It is overridden via
// -ldflags "-X github.com/ducduyn31/git-vault/internal/cli.Version=..."
// at release build time (see .goreleaser.yaml).
var Version = "dev"

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the git-vault version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), Version)
			return nil
		},
	}
}
