# Azure Key Vault Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `azurekms` as a third cloud KMS key provider for git-vault, mirroring the existing `gcpkms` provider exactly where Azure's SDK allows, and diverging only where Azure's actual behavior (version-pinned key URLs, credential-error shape) genuinely differs.

**Architecture:** A new `internal/keyservice/azurekms` package wraps sops's `github.com/getsops/sops/v3/azkv.MasterKey` (already a transitive dependency), following the identical `Provider{Name/Encrypt/Decrypt}` shape as `internal/keyservice/gcpkms`. It's wired through the same `vaultForProvider`/`install`/`login`/`rotate`/`migrate` functions gcpkms already uses, reusing the existing `KeyResourceID` and `AutoLogin` config fields — no new config field needed. A fake Key Vault server (`azurekmstest`, mirroring `gcpkmstest`) stands in for real Azure infrastructure in tests, using the official `azkeys/fake` package (an in-process HTTP transport double, no real listener). `git vault rotate` gets one piece of azurekms-specific logic beyond gcpkms's pattern: Azure Key Vault URLs are pinned to a specific key version, so rotating has to re-resolve the vault's current version and persist it to `.git-vault.yaml` before re-sealing.

**Tech Stack:** Go 1.23, `github.com/getsops/sops/v3/azkv`, `github.com/Azure/azure-sdk-for-go/sdk/{azcore,azidentity,security/keyvault/azkeys}` (all already transitive deps per go.mod), `github.com/stretchr/testify/require`, cobra.

## Global Constraints

- Reuse `config.Config.KeyResourceID` for the Key Vault key URL — no new config field (decided during brainstorming; Azure needs no analogue of AWS's `--aws-profile`).
- `--key-resource-id` for azurekms must be a fully-qualified Key Vault key URL **including the version** (`https://<vault>.vault.azure.net/keys/<name>/<version>`) — never resolved automatically. This deliberately diverges from sops's own `azkv.NewMasterKeyFromURL`, which does a live `GetKey` call to resolve "latest" when the version is omitted. `azurekms.Provider` parses the URL itself and calls `azkv.NewMasterKey` (which does zero network calls at construction) directly, so a missing version is a validation error, not a hidden background fetch.
- Credential-missing detection matches the substring `"DefaultAzureCredential: failed to acquire a token"` — confirmed empirically (twice: once via a direct `GetToken` call, once by simulating Key Vault's real 401 challenge-and-retry protocol end-to-end with a fake HTTP transport and the real, unmodified `DefaultAzureCredential`) to survive every layer of wrapping `azkv.MasterKey.EncryptContext`/`DecryptContext` add. This is git-vault's `azurekms.ErrNoCredentials`, exactly mirroring gcpkms's substring match on `"could not find default credentials"`.
- `git vault rotate` for `azurekms` is the **only** provider case that rewrites `.git-vault.yaml` — every other provider's rotate case leaves it untouched. This is because Azure's key URL is version-pinned; GCP's resource ID isn't.
- No new external Go module dependencies — `azure-sdk-for-go/sdk/{azcore,azidentity,security/keyvault/azkeys,security/keyvault/internal}` are already listed as indirect requires in go.mod; they just need to become direct (via `go mod tidy` in the final task).
- Full spec: `docs/superpowers/specs/2026-07-12-azurekms-provider-design.md`.

---

### Task 1: `azurekmstest` fake Key Vault server

**Files:**
- Create: `internal/keyservice/azurekms/azurekmstest/azurekmstest.go`
- Test: `internal/keyservice/azurekms/azurekmstest/azurekmstest_test.go`

**Interfaces:**
- Produces: `azurekmstest.NewFakeServer(vaultURL, keyName, currentVersion string) (azcore.TokenCredential, *azkeys.ClientOptions)` — consumed by Task 2 (`azurekms` package tests) and every CLI test task (3–7) that needs a fake Key Vault backend.

- [ ] **Step 1: Write the failing test**

Create `internal/keyservice/azurekms/azurekmstest/azurekmstest_test.go`:

```go
package azurekmstest

import (
	"bytes"
	"context"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/stretchr/testify/require"
)

const (
	testVaultURL = "https://test.vault.azure.net"
	testKeyName  = "test-key"
)

func TestFakeServer_EncryptDecrypt_RoundTrip(t *testing.T) {
	cred, opts := NewFakeServer(testVaultURL, testKeyName, "v1")
	client, err := azkeys.NewClient(testVaultURL, cred, opts)
	require.NoError(t, err)

	encResp, err := client.Encrypt(context.Background(), testKeyName, "v1", azkeys.KeyOperationParameters{
		Algorithm: to.Ptr(azkeys.EncryptionAlgorithmRSAOAEP256),
		Value:     []byte("sops data key"),
	}, nil)
	require.NoError(t, err)
	require.NotEqual(t, "sops data key", string(encResp.Result))

	decResp, err := client.Decrypt(context.Background(), testKeyName, "v1", azkeys.KeyOperationParameters{
		Algorithm: to.Ptr(azkeys.EncryptionAlgorithmRSAOAEP256),
		Value:     encResp.Result,
	}, nil)
	require.NoError(t, err)
	require.Equal(t, "sops data key", string(decResp.Result))
}

func TestFakeServer_Decrypt_TamperedCiphertextFails(t *testing.T) {
	cred, opts := NewFakeServer(testVaultURL, testKeyName, "v1")
	client, err := azkeys.NewClient(testVaultURL, cred, opts)
	require.NoError(t, err)

	_, err = client.Decrypt(context.Background(), testKeyName, "v1", azkeys.KeyOperationParameters{
		Algorithm: to.Ptr(azkeys.EncryptionAlgorithmRSAOAEP256),
		Value:     []byte("not a real wrapped key"),
	}, nil)
	require.Error(t, err)
}

func TestFakeServer_GetKey_ReportsConfiguredCurrentVersion(t *testing.T) {
	cred, opts := NewFakeServer(testVaultURL, testKeyName, "v7")
	client, err := azkeys.NewClient(testVaultURL, cred, opts)
	require.NoError(t, err)

	resp, err := client.GetKey(context.Background(), testKeyName, "", nil)
	require.NoError(t, err)
	require.Equal(t, "v7", resp.Key.KID.Version())
	require.True(t, bytes.HasPrefix([]byte(*resp.Key.KID), []byte(testVaultURL)))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/keyservice/azurekms/azurekmstest/... -v`
Expected: FAIL to compile — `undefined: NewFakeServer`

- [ ] **Step 3: Write the fake server**

Create `internal/keyservice/azurekms/azurekmstest/azurekmstest.go`:

```go
// Package azurekmstest provides a fake Azure Key Vault server for testing
// code that uses internal/keyservice/azurekms's Provider, without a real
// Azure tenant. It mirrors gcpkmstest's pattern, but uses the Azure SDK's
// own officially-supported fake transport (azkeys/fake) instead of a
// hand-rolled listener: fake.NewServerTransport implements
// policy.Transporter directly in-process, so there's no real network
// listener to start or clean up.
package azurekmstest

import (
	"bytes"
	"context"
	"fmt"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	azfake "github.com/Azure/azure-sdk-for-go/sdk/azcore/fake"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys/fake"
)

// marker prefixes every "ciphertext" this fake server produces, and is
// stripped back off on Decrypt — enough to prove real data flows through
// sops's azkv.MasterKey end-to-end without performing real cryptography
// or touching a real Azure tenant.
const marker = "fake-kv-wrapped:"

// NewFakeServer returns a fake credential and ClientOptions that redirect
// an azkv.MasterKey (or a raw azkeys.Client) to an in-process fake Key
// Vault, without a real Azure tenant or network call. currentVersion is
// what the fake's GetKey handler reports as the key's latest version
// (queried with an empty version parameter, Key Vault's convention for
// "latest") — used by tests of azurekms.Provider.CurrentVersionURL (and
// `git vault rotate`) to simulate a key that was rotated out-of-band in
// Azure.
func NewFakeServer(vaultURL, keyName, currentVersion string) (azcore.TokenCredential, *azkeys.ClientOptions) {
	srv := fake.Server{
		Encrypt: func(_ context.Context, _ string, _ string, parameters azkeys.KeyOperationParameters, _ *azkeys.EncryptOptions) (resp azfake.Responder[azkeys.EncryptResponse], errResp azfake.ErrorResponder) {
			resp.SetResponse(http.StatusOK, azkeys.EncryptResponse{
				KeyOperationResult: azkeys.KeyOperationResult{
					Result: append([]byte(marker), parameters.Value...),
				},
			}, nil)
			return resp, errResp
		},
		Decrypt: func(_ context.Context, _ string, _ string, parameters azkeys.KeyOperationParameters, _ *azkeys.DecryptOptions) (resp azfake.Responder[azkeys.DecryptResponse], errResp azfake.ErrorResponder) {
			if !bytes.HasPrefix(parameters.Value, []byte(marker)) {
				errResp.SetResponseError(http.StatusBadRequest, "BadParameter")
				return resp, errResp
			}
			resp.SetResponse(http.StatusOK, azkeys.DecryptResponse{
				KeyOperationResult: azkeys.KeyOperationResult{
					Result: parameters.Value[len(marker):],
				},
			}, nil)
			return resp, errResp
		},
		GetKey: func(_ context.Context, _ string, _ string, _ *azkeys.GetKeyOptions) (resp azfake.Responder[azkeys.GetKeyResponse], errResp azfake.ErrorResponder) {
			kid := azkeys.ID(fmt.Sprintf("%s/keys/%s/%s", vaultURL, keyName, currentVersion))
			resp.SetResponse(http.StatusOK, azkeys.GetKeyResponse{
				KeyBundle: azkeys.KeyBundle{Key: &azkeys.JSONWebKey{KID: &kid}},
			}, nil)
			return resp, errResp
		},
	}

	return &azfake.TokenCredential{}, &azkeys.ClientOptions{
		ClientOptions: azcore.ClientOptions{Transport: fake.NewServerTransport(&srv)},
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/keyservice/azurekms/azurekmstest/... -v`
Expected: PASS (all three tests)

- [ ] **Step 5: Commit**

```bash
git add internal/keyservice/azurekms/azurekmstest/
git commit -m "feat(azurekms): add fake Azure Key Vault server for testing"
```

---

### Task 2: `azurekms.Provider`

**Files:**
- Create: `internal/keyservice/azurekms/azurekms.go`
- Test: `internal/keyservice/azurekms/azurekms_test.go`

**Interfaces:**
- Consumes: `azurekmstest.NewFakeServer` (Task 1).
- Produces: `azurekms.Name = "azurekms"`, `azurekms.New() Provider`, `Provider.Name()/Encrypt(ctx, keyID, plaintext)/Decrypt(ctx, keyID, ciphertext)/CurrentVersionURL(ctx, keyID) (string, error)`, `azurekms.SetTestOverridesForTesting(cred azcore.TokenCredential, opts *azkeys.ClientOptions) (restore func())`, `azurekms.ErrNoCredentials` — all consumed by Tasks 3–7.

- [ ] **Step 1: Write the failing test**

Create `internal/keyservice/azurekms/azurekms_test.go`:

```go
package azurekms

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ducduyn31/git-vault/internal/keyservice/azurekms/azurekmstest"
)

const (
	testVaultURL = "https://test.vault.azure.net"
	testKeyName  = "test-key"
	testKeyURL   = testVaultURL + "/keys/" + testKeyName + "/v1"
)

func TestProvider_EncryptDecrypt_RoundTrip(t *testing.T) {
	cred, opts := azurekmstest.NewFakeServer(testVaultURL, testKeyName, "v1")
	restore := SetTestOverridesForTesting(cred, opts)
	defer restore()

	p := New()
	require.Equal(t, Name, p.Name())

	ciphertext, err := p.Encrypt(context.Background(), testKeyURL, []byte("sops data key"))
	require.NoError(t, err)
	require.NotEqual(t, "sops data key", string(ciphertext))

	plaintext, err := p.Decrypt(context.Background(), testKeyURL, ciphertext)
	require.NoError(t, err)
	require.Equal(t, "sops data key", string(plaintext))
}

func TestProvider_Decrypt_TamperedCiphertextFails(t *testing.T) {
	cred, opts := azurekmstest.NewFakeServer(testVaultURL, testKeyName, "v1")
	restore := SetTestOverridesForTesting(cred, opts)
	defer restore()

	p := New()
	_, err := p.Decrypt(context.Background(), testKeyURL, []byte("not a real wrapped key"))
	require.Error(t, err)
}

func TestProvider_Encrypt_MissingVersionFails(t *testing.T) {
	p := New()
	_, err := p.Encrypt(context.Background(), testVaultURL+"/keys/"+testKeyName, []byte("data"))
	require.ErrorContains(t, err, "not a valid Key Vault key URL")
}

func TestProvider_Encrypt_MalformedURLFails(t *testing.T) {
	p := New()
	_, err := p.Encrypt(context.Background(), "not-a-url", []byte("data"))
	require.ErrorContains(t, err, "not a valid Key Vault key URL")
}

func TestProvider_CurrentVersionURL_ResolvesLatest(t *testing.T) {
	cred, opts := azurekmstest.NewFakeServer(testVaultURL, testKeyName, "v2")
	restore := SetTestOverridesForTesting(cred, opts)
	defer restore()

	p := New()
	resolved, err := p.CurrentVersionURL(context.Background(), testKeyURL)
	require.NoError(t, err)
	require.Equal(t, testVaultURL+"/keys/"+testKeyName+"/v2", resolved)
}

func TestFriendlyLoginErr_RewritesMissingCredentialsMessage(t *testing.T) {
	err := friendlyLoginErr("encrypt", errors.New("failed to get Azure token credential to encrypt data: DefaultAzureCredential: failed to acquire a token.\nAttempted credentials:\n\tEnvironmentCredential: missing environment variable AZURE_TENANT_ID"))
	require.ErrorIs(t, err, ErrNoCredentials)
}

func TestFriendlyLoginErr_PassesThroughOtherErrors(t *testing.T) {
	err := friendlyLoginErr("encrypt", errors.New("permission denied"))
	require.ErrorContains(t, err, "azurekms: encrypt: permission denied")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/keyservice/azurekms/... -v`
Expected: FAIL to compile — `undefined: New`, `undefined: SetTestOverridesForTesting`, `undefined: ErrNoCredentials`, `undefined: friendlyLoginErr`

- [ ] **Step 3: Write the Provider**

Create `internal/keyservice/azurekms/azurekms.go`:

```go
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/keyservice/azurekms/... -v`
Expected: PASS (all tests in both `azurekms` and `azurekmstest`)

- [ ] **Step 5: Commit**

```bash
git add internal/keyservice/azurekms/azurekms.go internal/keyservice/azurekms/azurekms_test.go
git commit -m "feat(azurekms): add Provider wrapping sops's Azure Key Vault MasterKey"
```

---

### Task 3: Wire `azurekms` into `vaultForProvider`

**Files:**
- Modify: `internal/cli/vault.go`
- Test: `internal/cli/vault_test.go`

**Interfaces:**
- Consumes: `azurekms.New`, `azurekms.Name`, `azurekms.SetTestOverridesForTesting`, `azurekmstest.NewFakeServer` (Tasks 1–2).
- Produces: `newAzureKMSVault(cfg config.Config) (*vault.Vault, []string, error)`; `vaultForProvider` now handles `case azurekms.Name` — consumed by Tasks 4–7.

> **Note:** If `internal/cli/vault_test.go` does not exist yet, create it with `package cli` and the imports below; if it exists, add the test and imports to it.

- [ ] **Step 1: Write the failing test**

Add to `internal/cli/vault_test.go`:

```go
func TestVaultForProvider_AzureKMS(t *testing.T) {
	cred, opts := azurekmstest.NewFakeServer("https://test.vault.azure.net", "test-key", "v1")
	restore := azurekms.SetTestOverridesForTesting(cred, opts)
	defer restore()

	v, recipients, err := vaultForProvider(config.Config{
		Provider:      azurekms.Name,
		KeyResourceID: "https://test.vault.azure.net/keys/test-key/v1",
	})
	require.NoError(t, err)
	require.NotNil(t, v)
	require.Equal(t, []string{"azurekms:https://test.vault.azure.net/keys/test-key/v1"}, recipients)
}
```

Add these imports to `internal/cli/vault_test.go`'s import block (alongside `testing`, `github.com/stretchr/testify/require`, and `internal/config`):

```go
	"github.com/ducduyn31/git-vault/internal/keyservice/azurekms"
	"github.com/ducduyn31/git-vault/internal/keyservice/azurekms/azurekmstest"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cli/... -run TestVaultForProvider_AzureKMS -v`
Expected: FAIL — `git vault: unknown provider "azurekms" in .git-vault.yaml`

- [ ] **Step 3: Wire it in**

In `internal/cli/vault.go`, add the import `"github.com/ducduyn31/git-vault/internal/keyservice/azurekms"` (alongside the existing `gcpkms` import), then add this function after `newGCPKMSVault`:

```go
// newAzureKMSVault builds a Vault dispatching to Azure Key Vault, along
// with the "<provider>:<key-id>" recipient string for cfg.KeyResourceID
// (a fully-qualified Key Vault key URL, version included). Unlike
// local/passphrase, the key material lives entirely in Azure — this
// Provider holds no identity of its own beyond whatever
// DefaultAzureCredential resolves to.
func newAzureKMSVault(cfg config.Config) (*vault.Vault, []string, error) {
	registry := keyservice.NewRegistry()
	if err := registry.Register(azurekms.New()); err != nil {
		return nil, nil, err
	}
	server := keyservice.NewServer(registry)

	return vault.New(server), []string{azurekms.Name + ":" + cfg.KeyResourceID}, nil
}
```

Then add a case to `vaultForProvider`'s switch, right after `case gcpkms.Name`:

```go
	case azurekms.Name:
		return newAzureKMSVault(cfg)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/cli/... -v`
Expected: PASS (all tests in the package)

- [ ] **Step 5: Commit**

```bash
git add internal/cli/vault.go internal/cli/vault_test.go
git commit -m "feat(cli): wire azurekms into vaultForProvider"
```

---

### Task 4: `install --provider azurekms`

**Files:**
- Modify: `internal/cli/install.go`
- Test: `internal/cli/install_test.go`

**Interfaces:**
- Consumes: `newAzureKMSVault`/`vaultForProvider` azurekms case (Task 3); `verifyAzureKMSRoundTrip`/`attemptAzLogin` (Task 5).
- Produces: `install` accepts `--provider=azurekms`, requiring the existing `--key-resource-id` flag (no new flag).

> **Note on ordering:** This task's `RunE` calls `verifyAzureKMSRoundTrip` and `attemptAzLogin`, which Task 5 defines in `login.go`. Since Go compiles a package as a whole, implement Tasks 4 and 5 together if working sequentially in one session — there's no way to compile Task 4 alone without Task 5's functions existing. If using subagent-driven execution, give one worker both tasks' steps back-to-back before running tests.

- [ ] **Step 1: Write the failing tests**

Add to `internal/cli/install_test.go`:

```go
func TestInstallCmd_AzureKMS_WritesConfigAndValidates(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	cred, opts := azurekmstest.NewFakeServer("https://test.vault.azure.net", "test-key", "v1")
	restore := azurekms.SetTestOverridesForTesting(cred, opts)
	defer restore()

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{
		"install", "--provider=" + azurekms.Name,
		"--key-resource-id=https://test.vault.azure.net/keys/test-key/v1",
	})
	require.NoError(t, cmd.Execute())

	require.Contains(t, out.String(), "Recipient: azurekms:https://test.vault.azure.net/keys/test-key/v1")

	cfg, err := config.Load(config.DefaultFileName)
	require.NoError(t, err)
	require.Equal(t, azurekms.Name, cfg.Provider)
	require.Equal(t, "https://test.vault.azure.net/keys/test-key/v1", cfg.KeyResourceID)
}

func TestInstallCmd_AzureKMS_MissingKeyResourceIDFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"install", "--provider=" + azurekms.Name})

	err := cmd.Execute()
	require.ErrorContains(t, err, "--key-resource-id is required")
}

func TestInstallCmd_AzureKMS_FailsWithoutReachableVault(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"install", "--provider=" + azurekms.Name,
		"--key-resource-id=not-a-valid-url",
	})

	err := cmd.Execute()
	require.Error(t, err)

	_, gitErr := exec.Command("git", "config", "--get", "filter.git-vault.clean").Output()
	require.Error(t, gitErr, "git config must not be set when install fails the Key Vault round trip")
}
```

Add these imports to `internal/cli/install_test.go`'s import block:

```go
	"github.com/ducduyn31/git-vault/internal/keyservice/azurekms"
	"github.com/ducduyn31/git-vault/internal/keyservice/azurekms/azurekmstest"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cli/... -run TestInstallCmd_AzureKMS -v`
Expected: FAIL to compile — `undefined: verifyAzureKMSRoundTrip`, `undefined: attemptAzLogin` (until Task 5's code is also in place)

- [ ] **Step 3: Update install.go**

In `internal/cli/install.go`, add the import `"github.com/ducduyn31/git-vault/internal/keyservice/azurekms"` (alongside `gcpkms`).

Change:

```go
			if providerName == gcpkms.Name && keyResourceID == "" {
				return fmt.Errorf("git vault install: --key-resource-id is required for provider %q", gcpkms.Name)
			}
```

to:

```go
			if (providerName == gcpkms.Name || providerName == azurekms.Name) && keyResourceID == "" {
				return fmt.Errorf("git vault install: --key-resource-id is required for provider %q", providerName)
			}
```

Change:

```go
			if providerName == gcpkms.Name {
				err := verifyGCPKMSRoundTrip(cmd.Context(), keyResourceID)
				if errors.Is(err, gcpkms.ErrNoCredentials) && attemptGcloudLogin(cmd, autoLogin) {
					err = verifyGCPKMSRoundTrip(cmd.Context(), keyResourceID)
				}
				if err != nil {
					return fmt.Errorf("git vault install: %w", err)
				}
			}
```

to:

```go
			switch providerName {
			case gcpkms.Name:
				err := verifyGCPKMSRoundTrip(cmd.Context(), keyResourceID)
				if errors.Is(err, gcpkms.ErrNoCredentials) && attemptGcloudLogin(cmd, autoLogin) {
					err = verifyGCPKMSRoundTrip(cmd.Context(), keyResourceID)
				}
				if err != nil {
					return fmt.Errorf("git vault install: %w", err)
				}
			case azurekms.Name:
				err := verifyAzureKMSRoundTrip(cmd.Context(), keyResourceID)
				if errors.Is(err, azurekms.ErrNoCredentials) && attemptAzLogin(cmd, autoLogin) {
					err = verifyAzureKMSRoundTrip(cmd.Context(), keyResourceID)
				}
				if err != nil {
					return fmt.Errorf("git vault install: %w", err)
				}
			}
```

Finally, update the flag descriptions at the bottom of `newInstallCmd`:

```go
	cmd.Flags().String("provider", local.Name, "key provider to use (local, passphrase, gcpkms, azurekms)")
	cmd.Flags().String("key-resource-id", "", "GCP KMS resource ID or Azure Key Vault key URL (required when --provider gcpkms or azurekms)")
	cmd.Flags().Bool("auto-login", false, "skip the confirmation prompt and run the provider's login command automatically when credentials are missing (gcpkms, azurekms)")
```

- [ ] **Step 4: Run test to verify it passes**

This requires Task 5's `login.go` changes to be in place first (see the ordering note above). Once both are done, run:

Run: `go test ./internal/cli/... -v`
Expected: PASS (all tests in the package)

- [ ] **Step 5: Commit**

```bash
git add internal/cli/install.go internal/cli/install_test.go
git commit -m "feat(cli): accept --provider azurekms in install"
```

---

### Task 5: `login` support for `azurekms`

**Files:**
- Modify: `internal/cli/login.go`
- Test: `internal/cli/login_test.go`

**Interfaces:**
- Consumes: `azurekms.New`, `azurekms.Name`, `azurekms.ErrNoCredentials` (Task 2).
- Produces: `verifyAzureKMSRoundTrip(ctx context.Context, keyResourceID string) error`, `attemptAzLogin(cmd *cobra.Command, autoLogin bool) bool` — consumed by Task 4 (`install.go`) and Task 5 itself (`login.go`'s `RunE`). Also renames `gcpkmsLoginProbe` to `loginProbe` (shared by both providers) — no other file references the old name.

- [ ] **Step 1: Write the failing tests**

Add to `internal/cli/login_test.go`:

```go
func TestLoginCmd_AzureKMS_Succeeds(t *testing.T) {
	chdirTemp(t)
	require.NoError(t, config.Save(config.DefaultFileName, config.Config{
		Provider:      azurekms.Name,
		KeyResourceID: "https://test.vault.azure.net/keys/test-key/v1",
	}))

	cred, opts := azurekmstest.NewFakeServer("https://test.vault.azure.net", "test-key", "v1")
	restore := azurekms.SetTestOverridesForTesting(cred, opts)
	defer restore()

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{"login"})
	require.NoError(t, cmd.Execute())
	require.Contains(t, out.String(), "authorized")
}

func TestLoginCmd_AzureKMS_FailsWithoutReachableVault(t *testing.T) {
	chdirTemp(t)
	require.NoError(t, config.Save(config.DefaultFileName, config.Config{
		Provider:      azurekms.Name,
		KeyResourceID: "not-a-valid-url",
	}))

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"login"})
	require.Error(t, cmd.Execute())
}

func fakeAzCLI(t *testing.T, exitCode int) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake az script assumes a POSIX shell")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "az")
	contents := fmt.Sprintf("#!/bin/sh\nexit %d\n", exitCode)
	require.NoError(t, os.WriteFile(script, []byte(contents), 0o755))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestAttemptAzLogin_NoAzCLIOnPath(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	out := &bytes.Buffer{}
	require.False(t, attemptAzLogin(promptCmd(bytes.NewBufferString("y\n"), out), false))
	require.Empty(t, out.String())
}

func TestAttemptAzLogin_Declined(t *testing.T) {
	fakeAzCLI(t, 0)
	out := &bytes.Buffer{}
	require.False(t, attemptAzLogin(promptCmd(bytes.NewBufferString("n\n"), out), false))
	require.Contains(t, out.String(), "Run `az login` now?")
}

func TestAttemptAzLogin_ConfirmedAndCLISucceeds(t *testing.T) {
	fakeAzCLI(t, 0)
	out := &bytes.Buffer{}
	require.True(t, attemptAzLogin(promptCmd(bytes.NewBufferString("y\n"), out), false))
}

func TestAttemptAzLogin_ConfirmedButCLIFails(t *testing.T) {
	fakeAzCLI(t, 1)
	out := &bytes.Buffer{}
	require.False(t, attemptAzLogin(promptCmd(bytes.NewBufferString("yes\n"), out), false))
}

func TestAttemptAzLogin_AutoLoginSkipsPrompt(t *testing.T) {
	fakeAzCLI(t, 0)
	out := &bytes.Buffer{}
	require.True(t, attemptAzLogin(promptCmd(bytes.NewBufferString(""), out), true))
	require.Empty(t, out.String())
}

func TestAttemptAzLogin_AutoLoginStillNeedsCLI(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	out := &bytes.Buffer{}
	require.False(t, attemptAzLogin(promptCmd(bytes.NewBufferString(""), out), true))
}
```

Add these imports to `internal/cli/login_test.go`'s import block:

```go
	"github.com/ducduyn31/git-vault/internal/keyservice/azurekms"
	"github.com/ducduyn31/git-vault/internal/keyservice/azurekms/azurekmstest"
```

(`runtime`, `filepath`, `os`, `fmt` are already imported for `fakeGcloud`; `promptCmd` already exists — see Global Constraints of the codebase's existing `login_test.go`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cli/... -run 'TestLoginCmd_AzureKMS|TestAttemptAzLogin' -v`
Expected: FAIL to compile — `undefined: attemptAzLogin`

- [ ] **Step 3: Update login.go**

Replace `internal/cli/login.go` in full with:

```go
package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/keyservice/azurekms"
	"github.com/ducduyn31/git-vault/internal/keyservice/gcpkms"
)

// loginProbe is the fixed plaintext used to verify a KMS round trip. It
// carries no meaning beyond needing to survive Encrypt-then-Decrypt
// unchanged. Shared by every provider that uses git vault login.
const loginProbe = "git-vault-login-check"

func newLoginCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Verify this machine is authorized to use the repo's key provider",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}

			switch cfg.Provider {
			case gcpkms.Name:
				err = verifyGCPKMSRoundTrip(cmd.Context(), cfg.KeyResourceID)
				if errors.Is(err, gcpkms.ErrNoCredentials) && attemptGcloudLogin(cmd, cfg.AutoLogin) {
					err = verifyGCPKMSRoundTrip(cmd.Context(), cfg.KeyResourceID)
				}
				if err != nil {
					return fmt.Errorf("git vault login: %w", err)
				}
				_, err = fmt.Fprintln(cmd.OutOrStdout(), "GCP KMS round trip succeeded — this machine is authorized.")
				return err
			case azurekms.Name:
				err = verifyAzureKMSRoundTrip(cmd.Context(), cfg.KeyResourceID)
				if errors.Is(err, azurekms.ErrNoCredentials) && attemptAzLogin(cmd, cfg.AutoLogin) {
					err = verifyAzureKMSRoundTrip(cmd.Context(), cfg.KeyResourceID)
				}
				if err != nil {
					return fmt.Errorf("git vault login: %w", err)
				}
				_, err = fmt.Fprintln(cmd.OutOrStdout(), "Azure Key Vault round trip succeeded — this machine is authorized.")
				return err
			default:
				return fmt.Errorf("git vault login: provider %q does not use git vault login", cfg.Provider)
			}
		},
	}
}

// attemptGcloudLogin tries to fix a missing-ADC failure by running
// `gcloud auth application-default login` — the one gcpkms failure mode
// `login`/`install` can actually fix instead of just diagnosing. Unless
// autoLogin is set (config.Config.AutoLogin, a repo-committed
// opt-in), it asks for confirmation first: the command opens a browser
// and writes credentials to disk, which needs consent from a subcommand
// that's otherwise read-only. Returns whether gcloud ran successfully, in
// which case the caller should retry the round trip; false (declined, no
// gcloud on PATH, or a nonzero exit) leaves the original error in place.
func attemptGcloudLogin(cmd *cobra.Command, autoLogin bool) bool {
	path, err := exec.LookPath("gcloud")
	if err != nil {
		return false
	}

	if !autoLogin {
		if _, err := fmt.Fprint(cmd.OutOrStdout(), "No Google credentials found. Run `gcloud auth application-default login` now? [y/N] "); err != nil {
			return false
		}
		line, _ := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
		if answer := strings.ToLower(strings.TrimSpace(line)); answer != "y" && answer != "yes" {
			return false
		}
	}

	gcloudCmd := exec.CommandContext(cmd.Context(), path, "auth", "application-default", "login")
	gcloudCmd.Stdin = cmd.InOrStdin()
	gcloudCmd.Stdout = cmd.OutOrStdout()
	gcloudCmd.Stderr = cmd.ErrOrStderr()
	return gcloudCmd.Run() == nil
}

// attemptAzLogin tries to fix a missing-credentials failure
// (azurekms.ErrNoCredentials) by running `az login` — the one azurekms
// failure mode `login`/`install` can actually fix instead of just
// diagnosing. Mirrors attemptGcloudLogin's confirm-before-exec shape
// exactly, including the autoLogin (config.Config.AutoLogin) opt-out.
func attemptAzLogin(cmd *cobra.Command, autoLogin bool) bool {
	path, err := exec.LookPath("az")
	if err != nil {
		return false
	}

	if !autoLogin {
		if _, err := fmt.Fprint(cmd.OutOrStdout(), "No Azure credentials found. Run `az login` now? [y/N] "); err != nil {
			return false
		}
		line, _ := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
		if answer := strings.ToLower(strings.TrimSpace(line)); answer != "y" && answer != "yes" {
			return false
		}
	}

	azCmd := exec.CommandContext(cmd.Context(), path, "login")
	azCmd.Stdin = cmd.InOrStdin()
	azCmd.Stdout = cmd.OutOrStdout()
	azCmd.Stderr = cmd.ErrOrStderr()
	return azCmd.Run() == nil
}

// verifyGCPKMSRoundTrip encrypts and decrypts a fixed probe value against
// keyResourceID, returning an error (from gcpkms.Provider — see its
// friendlyLoginErr) if ADC is missing, IAM denies access, or the resource
// ID is malformed. Used by both `git vault login` and `git vault install`
// (to fail fast on a typo'd --key-resource-id).
func verifyGCPKMSRoundTrip(ctx context.Context, keyResourceID string) error {
	provider := gcpkms.New()
	ciphertext, err := provider.Encrypt(ctx, keyResourceID, []byte(loginProbe))
	if err != nil {
		return err
	}
	plaintext, err := provider.Decrypt(ctx, keyResourceID, ciphertext)
	if err != nil {
		return err
	}
	if string(plaintext) != loginProbe {
		return fmt.Errorf("gcpkms: round trip returned unexpected plaintext")
	}
	return nil
}

// verifyAzureKMSRoundTrip is verifyGCPKMSRoundTrip's Azure Key Vault
// equivalent — see its doc comment.
func verifyAzureKMSRoundTrip(ctx context.Context, keyResourceID string) error {
	provider := azurekms.New()
	ciphertext, err := provider.Encrypt(ctx, keyResourceID, []byte(loginProbe))
	if err != nil {
		return err
	}
	plaintext, err := provider.Decrypt(ctx, keyResourceID, ciphertext)
	if err != nil {
		return err
	}
	if string(plaintext) != loginProbe {
		return fmt.Errorf("azurekms: round trip returned unexpected plaintext")
	}
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/cli/... -v`
Expected: PASS (all tests in the package, including Task 4's install tests, now that both files are in place)

- [ ] **Step 5: Commit**

```bash
git add internal/cli/login.go internal/cli/login_test.go internal/cli/install.go internal/cli/install_test.go
git commit -m "feat(cli): add azurekms support to git vault login/install"
```

---

### Task 6: `rotate` support for `azurekms`

**Files:**
- Modify: `internal/cli/rotate.go`
- Test: `internal/cli/rotate_test.go`

**Interfaces:**
- Consumes: `vaultForProvider` azurekms case (Task 3); `azurekms.New().CurrentVersionURL` (Task 2).

- [ ] **Step 1: Write the failing tests**

Add to `internal/cli/rotate_test.go`:

```go
func TestRotateCmd_AzureKMS_ReResolvesVersionAndRoundTrips(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	// The fake reports "v2" as current, simulating a key that was
	// rotated in Azure (out-of-band) since the file was originally
	// sealed under "v1".
	cred, opts := azurekmstest.NewFakeServer("https://test.vault.azure.net", "test-key", "v2")
	restore := azurekms.SetTestOverridesForTesting(cred, opts)
	defer restore()

	original := setupTrackedEncryptedFileWithConfig(t, config.Config{
		Provider:      azurekms.Name,
		KeyResourceID: "https://test.vault.azure.net/keys/test-key/v1",
	})

	sealedBefore, err := os.ReadFile("secret.yaml")
	require.NoError(t, err)

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{"rotate"})
	require.NoError(t, cmd.Execute())
	require.Contains(t, out.String(), "Rotated 1 file")

	sealedAfter, err := os.ReadFile("secret.yaml")
	require.NoError(t, err)
	require.NotEqual(t, string(sealedBefore), string(sealedAfter), "rotate must force a fresh Key Vault Encrypt call")

	cfg, err := config.Load(config.DefaultFileName)
	require.NoError(t, err)
	require.Equal(t, "https://test.vault.azure.net/keys/test-key/v2", cfg.KeyResourceID, "rotate must persist the re-resolved current version")

	decryptCmd := NewRootCmd()
	decryptCmd.SetOut(&bytes.Buffer{})
	decryptCmd.SetArgs([]string{"decrypt", "secret.yaml"})
	require.NoError(t, decryptCmd.Execute())

	opened, err := os.ReadFile("secret.yaml")
	require.NoError(t, err)
	require.Equal(t, original, string(opened))
}
```

Add these imports to `internal/cli/rotate_test.go`'s import block:

```go
	"github.com/ducduyn31/git-vault/internal/keyservice/azurekms"
	"github.com/ducduyn31/git-vault/internal/keyservice/azurekms/azurekmstest"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cli/... -run TestRotateCmd_AzureKMS -v`
Expected: FAIL — `git vault rotate: rotation not supported for provider "azurekms"`

- [ ] **Step 3: Add the azurekms case**

In `internal/cli/rotate.go`, add the import `"github.com/ducduyn31/git-vault/internal/keyservice/azurekms"`.

Update the function's doc comment (it currently overclaims that `.git-vault.yaml` is never rewritten):

```go
// newRotateCmd re-seals every tracked file under fresh key material for
// the repo's *current* provider — unlike migrate, the provider name never
// changes. For every provider except azurekms, .git-vault.yaml is never
// rewritten either; azurekms is the one exception, since its key URL is
// pinned to a specific Key Vault key version (see its case below). See
// docs/superpowers/specs/2026-07-11-provider-key-rotation-design.md and
// docs/superpowers/specs/2026-07-12-azurekms-provider-design.md.
func newRotateCmd() *cobra.Command {
```

Add a case to the first `switch cfg.Provider` block, right after `case gcpkms.Name` (before `default`):

```go
		case azurekms.Name:
			// Azure Key Vault key URLs are version-pinned (unlike GCP's
			// resource ID), so if the key was rotated in Azure since
			// install or the last rotation, cfg.KeyResourceID may still
			// point at a stale version. Re-resolve to the vault's
			// current version first and persist it below, so re-sealing
			// actually moves every file onto that version instead of
			// re-encrypting under the old one.
			resolved, err := azurekms.New().CurrentVersionURL(cmd.Context(), cfg.KeyResourceID)
			if err != nil {
				return fmt.Errorf("git vault rotate: %w", err)
			}
			cfg.KeyResourceID = resolved
			newVault, newRecipients, err = vaultForProvider(cfg)
			if err != nil {
				return fmt.Errorf("git vault rotate: %w", err)
			}
			oldVault = newVault
```

Add a case to the second `switch cfg.Provider` block (the `followUp` message switch), right after `case gcpkms.Name`:

```go
		case azurekms.Name:
			followUp = "Old Key Vault key versions are still enabled to decrypt anything not yet migrated, including committed history. Once every commit that matters has been rotated, disable the old version in Azure to complete the rotation."
```

Finally, persist the re-resolved version to `.git-vault.yaml`. Change:

```go
			n, err := resealTracked(oldVault, newVault, newRecipients)
			if err != nil {
				return fmt.Errorf("git vault rotate: %w", err)
			}

			var followUp string
```

to:

```go
			n, err := resealTracked(oldVault, newVault, newRecipients)
			if err != nil {
				return fmt.Errorf("git vault rotate: %w", err)
			}

			if cfg.Provider == azurekms.Name {
				if err := config.Save(config.DefaultFileName, cfg); err != nil {
					return fmt.Errorf("git vault rotate: write %s: %w", config.DefaultFileName, err)
				}
			}

			var followUp string
```

(`config` is already imported in `rotate.go`.)

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/cli/... -v`
Expected: PASS (all tests in the package)

- [ ] **Step 5: Commit**

```bash
git add internal/cli/rotate.go internal/cli/rotate_test.go
git commit -m "feat(cli): support git vault rotate for azurekms"
```

---

### Task 7: `migrate` support for `azurekms`

**Files:**
- Modify: `internal/cli/migrate.go`
- Test: `internal/cli/migrate_test.go`

**Interfaces:**
- Consumes: `vaultForProvider` azurekms case (Task 3).

- [ ] **Step 1: Write the failing tests**

Add to `internal/cli/migrate_test.go`:

```go
func TestMigrateCmd_AzureKMSToAzureKMS_DifferentKey_RoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	cred, opts := azurekmstest.NewFakeServer("https://test.vault.azure.net", "test-key", "v1")
	restore := azurekms.SetTestOverridesForTesting(cred, opts)
	defer restore()

	original := setupTrackedEncryptedFileWithConfig(t, config.Config{
		Provider:      azurekms.Name,
		KeyResourceID: "https://test.vault.azure.net/keys/key-a/v1",
	})

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{
		"migrate", "--provider=" + azurekms.Name,
		"--key-resource-id=https://test.vault.azure.net/keys/key-b/v1",
	})
	require.NoError(t, cmd.Execute())
	require.Contains(t, out.String(), "Migrated 1 file")

	cfg, err := config.Load(config.DefaultFileName)
	require.NoError(t, err)
	require.Equal(t, azurekms.Name, cfg.Provider)
	require.Equal(t, "https://test.vault.azure.net/keys/key-b/v1", cfg.KeyResourceID)

	decryptCmd := NewRootCmd()
	decryptCmd.SetOut(&bytes.Buffer{})
	decryptCmd.SetArgs([]string{"decrypt", "secret.yaml"})
	require.NoError(t, decryptCmd.Execute())

	opened, err := os.ReadFile("secret.yaml")
	require.NoError(t, err)
	require.Equal(t, original, string(opened))
}

func TestMigrateCmd_AzureKMSToAzureKMS_SameKeyFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	cred, opts := azurekmstest.NewFakeServer("https://test.vault.azure.net", "test-key", "v1")
	restore := azurekms.SetTestOverridesForTesting(cred, opts)
	defer restore()

	setupTrackedEncryptedFileWithConfig(t, config.Config{
		Provider:      azurekms.Name,
		KeyResourceID: "https://test.vault.azure.net/keys/key-a/v1",
	})

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"migrate", "--provider=" + azurekms.Name,
		"--key-resource-id=https://test.vault.azure.net/keys/key-a/v1",
	})
	err := cmd.Execute()
	require.ErrorContains(t, err, "identical to the current key")
}

func TestMigrateCmd_AzureKMSTarget_MissingKeyResourceIDFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	setupTrackedEncryptedFile(t, local.Name)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"migrate", "--provider=" + azurekms.Name})

	err := cmd.Execute()
	require.ErrorContains(t, err, "--key-resource-id is required")
}
```

Add these imports to `internal/cli/migrate_test.go`'s import block:

```go
	"github.com/ducduyn31/git-vault/internal/keyservice/azurekms"
	"github.com/ducduyn31/git-vault/internal/keyservice/azurekms/azurekmstest"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cli/... -run TestMigrateCmd_AzureKMS -v`
Expected: FAIL to compile / fail — `TestMigrateCmd_AzureKMSTarget_MissingKeyResourceIDFails` fails because no `--key-resource-id` check exists for azurekms yet; the other two fail with `unknown provider "azurekms"`.

- [ ] **Step 3: Update migrate.go**

In `internal/cli/migrate.go`, add the import `"github.com/ducduyn31/git-vault/internal/keyservice/azurekms"` (alongside `gcpkms`).

Update the function's doc comment:

```go
// newMigrateCmd re-seals every tracked file from the repo's current
// provider/key to a different target, then updates .git-vault.yaml. A
// target that resolves to the exact same key as the current one is
// rejected rather than silently no-op'd: for local/passphrase that's
// always true (each has exactly one key source); for gcpkms/azurekms it's
// only true when the resource ID/URL also matches, since two different
// targets can share the provider name but name different keys. See
// docs/superpowers/specs/2026-07-11-migrate-provider-design.md,
// docs/superpowers/specs/2026-07-11-gcpkms-provider-design.md, and
// docs/superpowers/specs/2026-07-12-azurekms-provider-design.md.
func newMigrateCmd() *cobra.Command {
```

Change:

```go
			if target == gcpkms.Name && keyResourceID == "" {
				return fmt.Errorf("git vault migrate: --key-resource-id is required for provider %q", gcpkms.Name)
			}
```

to:

```go
			if (target == gcpkms.Name || target == azurekms.Name) && keyResourceID == "" {
				return fmt.Errorf("git vault migrate: --key-resource-id is required for provider %q", target)
			}
```

Finally, update the flag descriptions at the bottom of `newMigrateCmd`:

```go
	cmd.Flags().String("provider", "", "target key provider to migrate to (local, passphrase, gcpkms, azurekms)")
	cmd.Flags().String("key-resource-id", "", "GCP KMS resource ID or Azure Key Vault key URL (required when --provider gcpkms or azurekms)")
```

No other changes are needed: `vaultForProvider` (Task 3) and the existing resolved-recipient-string comparison already generalize to any provider whose identity is `provider + key ID`, not just gcpkms.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/cli/... -v`
Expected: PASS (all tests in the package)

- [ ] **Step 5: Commit**

```bash
git add internal/cli/migrate.go internal/cli/migrate_test.go
git commit -m "feat(cli): support git vault migrate for azurekms"
```

---

### Task 8: Documentation

**Files:**
- Create: `docs/azurekms-provider.md`
- Modify: `README.md`

**Interfaces:**
- None (docs only) — depends on the CLI surface from Tasks 4–7 being final so flag names/messages quoted in the docs match.

- [ ] **Step 1: Write the doc**

Create `docs/azurekms-provider.md`:

```markdown
# Azure Key Vault provider

git-vault's `azurekms` provider authorizes encrypt/decrypt through an
Azure Key Vault key, using whatever Azure credentials are already active
on your machine — `DefaultAzureCredential`. For most teams that means
`az login`, whether run directly or by whatever your org's Microsoft
Entra ID SSO already set up.

## 1. Admin bootstrap (one-time, done by whoever owns the Azure subscription)

    az keyvault create \
      --name git-vault-kv \
      --resource-group my-resource-group \
      --location eastus

    az keyvault key create \
      --vault-name git-vault-kv \
      --name git-vault-key \
      --kty RSA \
      --size 2048

    az role assignment create \
      --role "Key Vault Crypto User" \
      --assignee-object-id <group-or-user-object-id> \
      --scope $(az keyvault show --name git-vault-kv --query id -o tsv)

Note the key's fully-qualified URL, **including its version** (git-vault
requires the version explicitly — see Troubleshooting below):

    az keyvault key show \
      --vault-name git-vault-kv \
      --name git-vault-key \
      --query key.kid -o tsv

This prints something like
`https://git-vault-kv.vault.azure.net/keys/git-vault-key/abc123def456`.

## 2. Per-repo setup

    git vault install --provider azurekms \
      --key-resource-id https://git-vault-kv.vault.azure.net/keys/git-vault-key/abc123def456

This validates the URL immediately with a real encrypt/decrypt round
trip — a typo'd URL fails here, not at your first commit.

Add `--auto-login` to skip the confirmation prompt described below (see
"Auto-login" below) for every developer on this repo. It's persisted to
`.git-vault.yaml` as `auto_login: true`, so it's a one-time, team-wide,
repo-committed decision.

## 3. Per-developer setup

    git vault login

`git vault login` checks whether `DefaultAzureCredential` already
resolves to something that can use the configured key. If not, and `az`
is on your PATH, it offers to run `az login` for you (with confirmation
— it opens a browser and writes credentials to disk, so it never runs
without an explicit yes). Decline, or run it yourself first, and login
falls back to just telling you the exact command to run.

### Auto-login

If `.git-vault.yaml` has `auto_login: true` (see `--auto-login` above),
`git vault login` and `git vault install` skip the confirmation prompt
and run `az login` immediately when credentials are missing. Useful for
a team that's already decided every developer authenticates this way;
`az` still has to be on PATH, and it still opens a real browser window —
this only removes the extra keystroke, not the login flow itself.

## 4. Rotation

Azure Key Vault key rotation (automatic or via `az keyvault key rotate`)
only keeps old key versions passively decryptable — it never lets you
retire one, and the version baked into `.git-vault.yaml`'s
`key_resource_id` doesn't automatically follow a rotation performed in
Azure. Run `git vault rotate` periodically (or after a suspected key
exposure) to re-resolve the key's current version, persist it, and force
every tracked file's wrapped data key onto that version:

    git vault rotate
    git add -A && git commit -m "Rotate git-vault key"

Once every commit that matters has gone through a rotation, the old
version can be safely disabled:

    az keyvault key set-attributes \
      --vault-name git-vault-kv --name git-vault-key --version <old-version> \
      --enabled false

## Switching keys

To move to a different Key Vault key entirely (e.g. a different vault or
subscription), use `git vault migrate`, not `rotate` — `rotate` only
re-resolves the *current* version of the *same* key.

    git vault migrate --provider azurekms \
      --key-resource-id https://other-vault.vault.azure.net/keys/git-vault-key/<version>

## Troubleshooting

- `403` / access denied — your account isn't granted the `Key Vault
  Crypto User` role (or an access policy with wrap/unwrap key
  permissions) on the vault. Ask whoever ran the admin bootstrap step to
  add you (or your group).
- `"..." is not a valid Key Vault key URL, want https://<vault>.vault.azure.net/keys/<name>/<version>`
  — either the URL doesn't match that shape, or it's missing the version
  segment. git-vault always requires the version explicitly (no "latest"
  auto-resolution); copy the full value from `az keyvault key show
  --query key.kid`.
- "azurekms: no Azure credentials found — run `az login` first" —
  exactly that: no credential source (env vars, workload identity,
  managed identity, or a cached `az`/`azd`/PowerShell login) resolved on
  this machine yet.
```

- [ ] **Step 2: Update README.md**

Replace this paragraph:

```markdown
**Status:** early — encrypt/decrypt, the clean/smudge filter, status
reporting, key rotation, and cross-provider migration all work today.
GCP KMS is available as a first team key-sharing provider, authorized
through your org's existing Google Workspace SSO — see
[docs/gcpkms-provider.md](docs/gcpkms-provider.md). Other cloud
providers (AWS, Azure) are on the roadmap.
```

with:

```markdown
**Status:** early — encrypt/decrypt, the clean/smudge filter, status
reporting, key rotation, and cross-provider migration all work today.
GCP KMS and Azure Key Vault are available as team key-sharing providers,
authorized through your org's existing Google Workspace or Microsoft
Entra ID SSO — see [docs/gcpkms-provider.md](docs/gcpkms-provider.md)
and [docs/azurekms-provider.md](docs/azurekms-provider.md). AWS is on
the roadmap.
```

Then replace this section:

```markdown
## Team key-sharing with GCP KMS

For a shared key backed by your org's existing SSO (rather than a local
per-machine key or an out-of-band passphrase), see
[docs/gcpkms-provider.md](docs/gcpkms-provider.md).
```

with:

```markdown
## Team key-sharing with cloud KMS

For a shared key backed by your org's existing SSO (rather than a local
per-machine key or an out-of-band passphrase), see
[docs/gcpkms-provider.md](docs/gcpkms-provider.md) (Google Workspace
SSO) or [docs/azurekms-provider.md](docs/azurekms-provider.md)
(Microsoft Entra ID / `az login`).
```

- [ ] **Step 3: Verify the docs read correctly**

Run: `cat docs/azurekms-provider.md` and skim it end-to-end; run `grep -n "azurekms\|Azure" README.md` to confirm both edits landed and no stale "(AWS, Azure) are on the roadmap" mention remains.
Expected: `docs/azurekms-provider.md` prints in full with no `TBD`; `README.md` no longer contains "(AWS, Azure) are on the roadmap".

- [ ] **Step 4: Commit**

```bash
git add docs/azurekms-provider.md README.md
git commit -m "docs: add Azure Key Vault provider guide, link it from README"
```

---

### Task 9: Dependency tidy and full verification

**Files:**
- Modify: `go.mod`, `go.sum` (via `go mod tidy`, not hand-edited)

**Interfaces:**
- None — this is a whole-repo sanity pass after Tasks 1–8.

- [ ] **Step 1: Tidy go.mod**

Run: `go mod tidy`
Expected: exits 0; `git diff go.mod` shows `github.com/Azure/azure-sdk-for-go/sdk/{azcore,azidentity,security/keyvault/azkeys,security/keyvault/internal}` (among others already indirect) lose the `// indirect` marker. No new module should be added — these were already present as transitive dependencies.

- [ ] **Step 2: Run the full test suite**

Run: `go test ./...`
Expected: PASS, all packages, no skips other than the pre-existing Windows-only skips (`fakeGcloud`, `fakeAzCLI`).

- [ ] **Step 3: Run the build and lint tasks**

Run: `task build`
Expected: builds the `git-vault` binary with no errors.

Run: `task lint`
Expected: exits 0 (or matches whatever pre-existing lint baseline the repo has — do not introduce new findings).

- [ ] **Step 4: Manual smoke test against the real CLI**

```bash
cd "$(mktemp -d)" && git init -q
/path/to/git-vault install --provider azurekms --key-resource-id https://x.vault.azure.net/keys/k
```

Expected: fails fast with `"https://x.vault.azure.net/keys/k" is not a valid Key Vault key URL, want https://<vault>.vault.azure.net/keys/<name>/<version>` (the version segment is missing — no network call happens), and `git config --get filter.git-vault.clean` returns nothing (install didn't get past validation).

- [ ] **Step 5: Commit**

```bash
git add go.mod go.sum
git commit -m "chore: go mod tidy after adding the azurekms provider"
```
</content>
