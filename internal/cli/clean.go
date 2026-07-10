package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newCleanCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "clean [path]",
		Short:  "Git clean filter entry point (encrypt on stage)",
		Args:   cobra.MaximumNArgs(1),
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("git vault clean: not implemented in scaffold")
		},
	}
}
