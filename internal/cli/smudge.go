package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newSmudgeCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "smudge [path]",
		Short:  "Git smudge filter entry point (decrypt on checkout)",
		Args:   cobra.MaximumNArgs(1),
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("git vault smudge: not implemented in scaffold")
		},
	}
}
