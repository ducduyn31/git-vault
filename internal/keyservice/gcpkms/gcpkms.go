// Package gcpkms implements a keyservice.Provider backed by GCP Cloud
// KMS, authorized via whatever Google Application Default Credentials
// (ADC) are active on this machine — for most teams, that's already
// SSO'd through Google Workspace via `gcloud auth application-default
// login`. Unlike internal/keyservice/local and
// internal/keyservice/passphrase, git-vault holds no key material of its
// own here: GCP IAM on the KMS key is the only access control, and
// git-vault never runs its own OAuth flow — `git vault login`
// (internal/cli/login.go) only ever shells out to the real `gcloud auth
// application-default login`, and only with the user's explicit
// confirmation. See docs/superpowers/specs/2026-07-11-gcpkms-provider-design.md.
package gcpkms

import (
	"context"
	"errors"
	"fmt"
	"strings"

	sopsgcpkms "github.com/getsops/sops/v3/gcpkms"
	"google.golang.org/api/option"
)

// Name is the provider name used in "gcpkms:<resource-id>" key
// identifiers (see internal/keyservice.Server).
const Name = "gcpkms"

// testClientOptions overrides every MasterKey this package's Providers
// create. Set only via SetClientOptionsForTesting.
var testClientOptions []option.ClientOption

// SetClientOptionsForTesting points every Provider subsequently created
// by New at a fake GCP KMS gRPC server instead of real GCP
// infrastructure (see the gcpkmstest package). It returns a function
// that restores the previous options — call it via defer. For use in
// tests only.
func SetClientOptionsForTesting(opts []option.ClientOption) (restore func()) {
	prev := testClientOptions
	testClientOptions = opts
	return func() { testClientOptions = prev }
}

// Provider is backed by a GCP KMS key, identified per-call by keyID (a
// KMS resource ID) rather than fixed at construction — the resource ID
// lives in git-vault's repo-tracked config
// (internal/config.Config.KeyResourceID), not in this Provider.
type Provider struct {
	clientOptions []option.ClientOption
}

// New returns a Provider using real GCP KMS, unless
// SetClientOptionsForTesting has redirected it to a fake server.
func New() Provider {
	return Provider{clientOptions: testClientOptions}
}

func (p Provider) Name() string { return Name }

// Encrypt wraps plaintext (a sops data key) with the GCP KMS key named by
// keyID (a resource ID of the form
// projects/P/locations/L/keyRings/R/cryptoKeys/K).
func (p Provider) Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error) {
	key := sopsgcpkms.NewMasterKeyFromResourceID(keyID)
	sopsgcpkms.ClientOptions(p.clientOptions).ApplyToMasterKey(key)
	if err := key.EncryptContext(ctx, plaintext); err != nil {
		return nil, friendlyLoginErr("encrypt", err)
	}
	return key.EncryptedDataKey(), nil
}

// Decrypt unwraps ciphertext (see Encrypt) with the GCP KMS key named by
// keyID.
func (p Provider) Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error) {
	key := sopsgcpkms.NewMasterKeyFromResourceID(keyID)
	sopsgcpkms.ClientOptions(p.clientOptions).ApplyToMasterKey(key)
	key.SetEncryptedDataKey(ciphertext)
	plaintext, err := key.DecryptContext(ctx)
	if err != nil {
		return nil, friendlyLoginErr("decrypt", err)
	}
	return plaintext, nil
}

// ErrNoCredentials is returned (via friendlyLoginErr) when Application
// Default Credentials can't be found anywhere in their default chain.
// It's a sentinel rather than just a message so callers — namely
// internal/cli/login.go — can detect this specific, fixable case with
// errors.Is and offer to run the command themselves, instead of every
// caller re-parsing error text.
var ErrNoCredentials = errors.New("gcpkms: no Google credentials found — run `gcloud auth application-default login` first")

// friendlyLoginErr rewrites the fixed error golang.org/x/oauth2/google
// emits when Application Default Credentials can't be found anywhere in
// its default chain into ErrNoCredentials. There is no exported
// sentinel error for this case in the Google auth libraries, so a
// substring match on that fixed message is the same technique gcloud
// itself and most third-party tools use to detect it. Any other error
// (e.g. IAM permission denied, malformed resource ID) is wrapped with op
// but otherwise passed through as-is.
func friendlyLoginErr(op string, err error) error {
	if strings.Contains(err.Error(), "could not find default credentials") {
		return ErrNoCredentials
	}
	return fmt.Errorf("gcpkms: %s: %w", op, err)
}
