package cli

import (
	"bytes"
	"io"

	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/gitcmd"
	"github.com/ducduyn31/git-vault/internal/provider"
	"github.com/ducduyn31/git-vault/internal/vault"
)

func newCleanCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "clean <path>",
		Short:  "Git clean filter entry point (encrypt on stage)",
		Args:   cobra.ExactArgs(1),
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			format := vault.FormatForPath(path)

			v, recipients, err := provider.Current()
			if err != nil {
				return err
			}

			plaintext, err := io.ReadAll(cmd.InOrStdin())
			if err != nil {
				return err
			}

			if stored, ok := unchangedFromIndex(v, path, format, plaintext); ok {
				_, err := cmd.OutOrStdout().Write(stored)
				return err
			}

			return v.SealStream(cmd.OutOrStdout(), bytes.NewReader(plaintext), format, recipients)
		},
	}
}

// unchangedFromIndex returns the blob git has staged for path when that
// blob decrypts to exactly plaintext, meaning the working tree file has
// not really changed. Emitting the stored blob verbatim is what keeps
// tracked files from reporting as permanently modified: sops mints a
// fresh random data key on every seal, so re-sealing identical plaintext
// yields different bytes, and git's dirty check (clean the working tree
// file, compare to the staged blob) would never agree.
//
// The stored blob must itself be sealed for the shortcut to apply —
// otherwise a file staged as plaintext before git-vault was installed
// would match itself and never get encrypted. Any other failure (no
// index entry, unreadable blob, wrong key, bad MAC) just declines the
// shortcut and lets the caller seal; the filter is required=true, so an
// error here would abort the user's git command.
func unchangedFromIndex(v *vault.Vault, path string, format vault.Format, plaintext []byte) ([]byte, bool) {
	stored, ok := gitcmd.IndexBlob(path)
	if !ok || !vault.IsSealedBytes(stored, format) {
		return nil, false
	}

	var opened bytes.Buffer
	if err := v.OpenStream(&opened, bytes.NewReader(stored), format); err != nil {
		return nil, false
	}
	if !bytes.Equal(opened.Bytes(), plaintext) {
		return nil, false
	}
	return stored, true
}
