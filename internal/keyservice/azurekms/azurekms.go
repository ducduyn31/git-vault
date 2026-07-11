// Package azurekms implements a keyservice.Provider backed by Azure Key
// Vault, authorized via whatever credentials
// azidentity.DefaultAzureCredential resolves on this machine (env vars,
// workload identity, managed identity, or — for local/team use — the
// `az` CLI's cached login from `az login`). Unlike internal/keyservice/local
// and internal/keyservice/passphrase, git-vault holds no key material of
// its own here: Azure RBAC/access policy on the Key Vault key is the only
// access control, and git-vault never runs its own device-code flow —
// `git vault login` (internal/cli/login.go) only ever shells out to the
// real `az login`, and only with the user's explicit confirmation (or
// config.Config.AutoLogin). See
// docs/superpowers/specs/2026-07-12-azurekms-provider-design.md.
package azurekms

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	sopsazkv "github.com/getsops/sops/v3/azkv"
)

// Name is the provider name used in "azurekms:<key-url>" key identifiers
// (see internal/keyservice.Server).
const Name = "azurekms"

// testCredential and testClientOptions override every MasterKey this
// package's Providers create. Set only via SetTestOverridesForTesting.
var (
	testCredential    azcore.TokenCredential
	testClientOptions *azkeys.ClientOptions
)

// SetTestOverridesForTesting points every Provider subsequently created
// by New at a fake Key Vault server instead of real Azure infrastructure
// (see the azurekmstest package), and supplies a fake credential so no
// real credential chain lookup happens. It returns a function that
// restores the previous overrides — call it via defer. For use in tests
// only.
func SetTestOverridesForTesting(cred azcore.TokenCredential, opts *azkeys.ClientOptions) (restore func()) {
	prevCred, prevOpts := testCredential, testClientOptions
	testCredential, testClientOptions = cred, opts
	return func() { testCredential, testClientOptions = prevCred, prevOpts }
}

// Provider is backed by an Azure Key Vault key, identified per-call by
// keyID (a fully-qualified Key Vault key URL, version included) rather
// than fixed at construction — the URL lives in git-vault's repo-tracked
// config (internal/config.Config.KeyResourceID), not in this Provider.
type Provider struct {
	credential    azcore.TokenCredential
	clientOptions *azkeys.ClientOptions
}

// New returns a Provider using real Azure Key Vault, unless
// SetTestOverridesForTesting has redirected it to a fake server.
func New() Provider {
	return Provider{credential: testCredential, clientOptions: testClientOptions}
}

func (p Provider) Name() string { return Name }

// Encrypt wraps plaintext (a sops data key) with the Key Vault key named
// by keyID (a URL of the form
// https://<vault>.vault.azure.net/keys/<name>/<version>).
func (p Provider) Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error) {
	vaultURL, name, version, err := parseKeyURL(keyID)
	if err != nil {
		return nil, fmt.Errorf("azurekms: %w", err)
	}
	key := sopsazkv.NewMasterKey(vaultURL, name, version)
	p.apply(key)
	if err := key.EncryptContext(ctx, plaintext); err != nil {
		return nil, friendlyLoginErr("encrypt", err)
	}
	return key.EncryptedDataKey(), nil
}

// Decrypt unwraps ciphertext (see Encrypt) with the Key Vault key named
// by keyID.
func (p Provider) Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error) {
	vaultURL, name, version, err := parseKeyURL(keyID)
	if err != nil {
		return nil, fmt.Errorf("azurekms: %w", err)
	}
	key := sopsazkv.NewMasterKey(vaultURL, name, version)
	p.apply(key)
	key.SetEncryptedDataKey(ciphertext)
	plaintext, err := key.DecryptContext(ctx)
	if err != nil {
		return nil, friendlyLoginErr("decrypt", err)
	}
	return plaintext, nil
}

// apply configures key with this Provider's test overrides, if any.
func (p Provider) apply(key *sopsazkv.MasterKey) {
	if p.credential != nil {
		sopsazkv.NewTokenCredential(p.credential).ApplyToMasterKey(key)
	}
	if p.clientOptions != nil {
		sopsazkv.NewClientOptions(p.clientOptions).ApplyToMasterKey(key)
	}
}

// CurrentVersionURL resolves keyID's vault+name to whichever key version
// Azure Key Vault currently reports as latest, returning the fully
// qualified URL (.../keys/<name>/<version>). Used by `git vault rotate`
// to move the repo's configured key_resource_id onto a version that may
// have changed since install or the last rotation — Azure's URL is
// version-pinned, unlike GCP's resource ID, so git-vault has to track
// this explicitly instead of letting it happen implicitly server-side.
func (p Provider) CurrentVersionURL(ctx context.Context, keyID string) (string, error) {
	vaultURL, name, _, err := parseKeyURL(keyID)
	if err != nil {
		return "", fmt.Errorf("azurekms: %w", err)
	}

	cred := p.credential
	if cred == nil {
		cred, err = azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return "", fmt.Errorf("azurekms: resolve current version: %w", err)
		}
	}
	client, err := azkeys.NewClient(vaultURL, cred, p.clientOptions)
	if err != nil {
		return "", fmt.Errorf("azurekms: resolve current version: %w", err)
	}
	resp, err := client.GetKey(ctx, name, "", nil)
	if err != nil {
		return "", friendlyLoginErr("resolve current version", err)
	}
	return fmt.Sprintf("%s/keys/%s/%s", vaultURL, name, resp.Key.KID.Version()), nil
}

// keyURLPattern matches a fully-qualified Key Vault key URL. Unlike
// sops's own azkv package (whose URL parsing accepts an optional
// version), the version group here is mandatory — see this plan's
// Global Constraints and the design spec's "Key identifier" section.
var keyURLPattern = regexp.MustCompile(`^(https://[^/]+)/keys/([^/]+)/([^/]+)$`)

// parseKeyURL splits a fully-qualified Azure Key Vault key URL into its
// vault URL, key name, and version.
func parseKeyURL(url string) (vaultURL, name, version string, err error) {
	parts := keyURLPattern.FindStringSubmatch(strings.TrimSpace(url))
	if parts == nil {
		return "", "", "", fmt.Errorf("%q is not a valid Key Vault key URL, want https://<vault>.vault.azure.net/keys/<name>/<version>", url)
	}
	return parts[1], parts[2], parts[3], nil
}

// ErrNoCredentials is returned (via friendlyLoginErr) when
// DefaultAzureCredential's entire credential chain fails to acquire a
// token. It's a sentinel rather than just a message so callers — namely
// internal/cli/login.go — can detect this specific, fixable case with
// errors.Is and offer to run `az login` themselves, instead of every
// caller re-parsing error text.
var ErrNoCredentials = errors.New("azurekms: no Azure credentials found — run `az login` first")

// friendlyLoginErr rewrites a total-chain credential failure into
// ErrNoCredentials. DefaultAzureCredential's own error type
// (credentialUnavailableError) is unexported, so — like gcpkms's
// substring match on "could not find default credentials" — this
// matches on the fixed message prefix
// "DefaultAzureCredential: failed to acquire a token", present whenever
// every source in the chain fails regardless of which sources were
// tried or why each one individually failed (confirmed empirically —
// see this plan's Global Constraints). Any other error (e.g. RBAC/access
// policy denial, malformed key URL) is wrapped with op but otherwise
// passed through as-is.
func friendlyLoginErr(op string, err error) error {
	if strings.Contains(err.Error(), "DefaultAzureCredential: failed to acquire a token") {
		return ErrNoCredentials
	}
	return fmt.Errorf("azurekms: %s: %w", op, err)
}
