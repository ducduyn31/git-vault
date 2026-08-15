package provider

import (
	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/keyservice"
	"github.com/ducduyn31/git-vault/internal/keyservice/hcvault"
	"github.com/ducduyn31/git-vault/internal/vault"
)

// newHCVault holds no identity of its own: the key lives in Vault's
// Transit engine and credentials come from the bearer token in
// VAULT_TOKEN or ~/.vault-token.
func newHCVault(cfg config.Config) (*vault.Vault, []string, error) {
	return build(hcvault.New(), cfg.KeyResourceID)
}

// hcVaultRemote logs in with the default token method; orgs on OIDC,
// LDAP, GitHub, or AppRole run their own `vault login -method=...` first.
var hcVaultRemote = Remote{
	Display:   "Vault Transit",
	LoginErr:  hcvault.ErrNoValidToken,
	LoginHint: "No valid Vault token found.",
	LoginArgv: func(config.Config) []string { return []string{"vault", "login"} },
	new:       func(config.Config) keyservice.Provider { return hcvault.New() },
}
