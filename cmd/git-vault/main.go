package main

import (
	"os"

	"github.com/ducduyn31/git-vault/internal/cli"
	"github.com/ducduyn31/git-vault/internal/ui"
)

func main() {
	if err := cli.Execute(); err != nil {
		ui.Error(os.Stderr, err)
		os.Exit(1)
	}
}
