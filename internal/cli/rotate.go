package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/keyservice/awskms"
	"github.com/ducduyn31/git-vault/internal/keyservice/azurekms"
	"github.com/ducduyn31/git-vault/internal/keyservice/gcpkms"
	"github.com/ducduyn31/git-vault/internal/keyservice/hcvault"
	"github.com/ducduyn31/git-vault/internal/keyservice/local"
	"github.com/ducduyn31/git-vault/internal/keyservice/passphrase"
	"github.com/ducduyn31/git-vault/internal/provider"
	"github.com/ducduyn31/git-vault/internal/ui"
)

// rotateFollowUp tells the user what rotation left behind for them to
// clean up: which old key material still decrypts history, and how to
// retire it once every commit that matters has been re-sealed.
var rotateFollowUp = map[string]string{
	local.Name:      "Old identity is retained to decrypt anything not yet migrated (including committed history).",
	passphrase.Name: "Distribute the new passphrase to your team out-of-band, and keep GIT_VAULT_PASSPHRASE set to the old value followed by the new value (one per line) until everyone has migrated — then the old line can be dropped.",
	gcpkms.Name:     "Old KMS key versions are still enabled to decrypt anything not yet migrated, including committed history. Once every commit that matters has been rotated, disable or destroy the old version(s) in GCP to complete the rotation.",
	awskms.Name:     "AWS KMS rotates its backing key material automatically and transparently — unlike GCP, there is no old version to disable or destroy afterward; this re-encryption is defense-in-depth only. To actually retire a compromised key, use `git vault migrate` to a different KMS key instead.",
	hcvault.Name:    "Vault Transit key versions are still enabled to decrypt anything not yet migrated, including committed history (governed by the key's min_decryption_version). Once every commit that matters has been rotated, run `vault write transit/keys/<name>/config min_decryption_version=<new-version>` to retire the old version(s).",
	azurekms.Name:   "Old Key Vault key versions are still enabled to decrypt anything not yet migrated, including committed history. Once every commit that matters has been rotated, disable the old version in Azure to complete the rotation.",
}

// newRotateCmd re-seals every tracked file under fresh key material for
// the repo's *current* provider — unlike migrate, the provider name never
// changes. .git-vault.yaml is rewritten only when rotation changed it,
// which today means azurekms alone: its key URL pins a key version.
func newRotateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rotate",
		Short: "Generate a new key and re-seal all tracked files under it",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := provider.LoadConfig()
			if err != nil {
				return err
			}

			rot, err := provider.Rotate(cmd.Context(), cmd.OutOrStdout(), cfg)
			if err != nil {
				return fmt.Errorf("git vault rotate: %w", err)
			}

			n, err := provider.ResealTracked(rot.Old, rot.New, rot.Recipients)
			if err != nil {
				return fmt.Errorf("git vault rotate: %w", err)
			}

			if rot.Config != cfg {
				if err := config.Save(config.DefaultFileName, rot.Config); err != nil {
					return fmt.Errorf("git vault rotate: write %s: %w", config.DefaultFileName, err)
				}
			}

			ui.New(cmd.OutOrStdout()).Info(fmt.Sprintf(
				"Rotated %d file(s) under %q.\n%s\nRun `git add -A && git commit` to finish — committed ciphertext still needs the old key until you do.",
				n, cfg.Provider, rotateFollowUp[cfg.Provider],
			))
			return nil
		},
	}
}
