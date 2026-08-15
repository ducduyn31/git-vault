package provider

import (
	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/keyservice"
	"github.com/ducduyn31/git-vault/internal/keyservice/awskms"
	"github.com/ducduyn31/git-vault/internal/vault"
)

// newAWSKMS holds no identity of its own: the key lives in AWS (keyed by
// ARN) and credentials come from cfg.AwsProfile or the default chain.
func newAWSKMS(cfg config.Config) (*vault.Vault, []string, error) {
	return build(awskms.New(cfg.AwsProfile), cfg.KeyResourceID)
}

// awsKMSRemote covers the expired-SSO failure only; AWS's others (never
// configured, permission denied) are deliberately out of scope
var awsKMSRemote = Remote{
	Display:   "AWS KMS",
	LoginErr:  awskms.ErrExpiredSSOSession,
	LoginHint: "AWS SSO session expired or missing.",
	LoginArgv: func(cfg config.Config) []string {
		argv := []string{"aws", "sso", "login"}
		if cfg.AwsProfile != "" {
			argv = append(argv, "--profile", cfg.AwsProfile)
		}
		return argv
	},
	new: func(cfg config.Config) keyservice.Provider { return awskms.New(cfg.AwsProfile) },
}
