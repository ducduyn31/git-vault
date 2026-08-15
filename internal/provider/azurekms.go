package provider

import (
	"context"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/keyservice"
	"github.com/ducduyn31/git-vault/internal/keyservice/azurekms"
	"github.com/ducduyn31/git-vault/internal/vault"
)

// newAzureKMS holds no identity of its own: the key lives in Azure (keyed
// by a version-pinned URL) and credentials come from
// DefaultAzureCredential.
func newAzureKMS(cfg config.Config) (*vault.Vault, []string, error) {
	return build(azurekms.New(), cfg.KeyResourceID)
}

var azureKMSRemote = Remote{
	Display:   "Azure Key Vault",
	LoginErr:  azurekms.ErrNoCredentials,
	LoginHint: "No Azure credentials found.",
	LoginArgv: func(config.Config) []string { return []string{"az", "login"} },
	new:       func(config.Config) keyservice.Provider { return azurekms.New() },
}

// rotateAzureKMS re-resolves the key URL first: it is version-pinned, so
// a key rotated in Azure leaves cfg.KeyResourceID naming a stale version
// and re-sealing would land back on it. The returned Config carries the
// resolved URL for the caller to persist.
func rotateAzureKMS(ctx context.Context, cfg config.Config) (Rotation, error) {
	resolved, err := azurekms.New().CurrentVersionURL(ctx, cfg.KeyResourceID)
	if err != nil {
		return Rotation{}, err
	}
	cfg.KeyResourceID = resolved
	return reseal(cfg)
}
