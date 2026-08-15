package provider

import (
	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/keyservice"
	"github.com/ducduyn31/git-vault/internal/keyservice/gcpkms"
	"github.com/ducduyn31/git-vault/internal/vault"
)

// newGCPKMS holds no identity of its own: the key lives in GCP and
// credentials come from ADC.
func newGCPKMS(cfg config.Config) (*vault.Vault, []string, error) {
	return build(gcpkms.New(), cfg.KeyResourceID)
}

var gcpKMSRemote = Remote{
	Display:   "GCP KMS",
	LoginErr:  gcpkms.ErrNoCredentials,
	LoginHint: "No Google credentials found.",
	LoginArgv: func(config.Config) []string {
		return []string{"gcloud", "auth", "application-default", "login"}
	},
	new: func(config.Config) keyservice.Provider { return gcpkms.New() },
}
