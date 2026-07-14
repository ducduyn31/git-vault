# HashiCorp Vault Transit Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `--provider vault`, a `keyservice.Provider` backed by HashiCorp Vault's Transit secrets engine, wired through every command (`install`, `login`, `rotate`, `migrate`) the same way gcpkms/awskms/azurekms already are.

**Architecture:** A stateless `hcvault.Provider` (package `internal/keyservice/hcvault`) wraps sops's existing `github.com/getsops/sops/v3/hcvault.MasterKey`, constructed per-call via `hcvault.NewMasterKeyFromURI(keyID)` — no hand-rolled URL parsing. Auth is a bearer token resolved by sops itself (`VAULT_TOKEN` env, then `~/.vault-token`); `git vault login`/`install` classify a Vault 403 into a sentinel error and offer to run `vault login` to fix it, mirroring `az login`/`gcloud auth ... login`. No version pinning is needed in `--key-resource-id` (unlike azurekms) because Vault Transit ciphertext embeds its own key version.

**Tech Stack:** Go, `github.com/hashicorp/vault/api` (already an indirect dependency via sops, promoted to direct), `github.com/getsops/sops/v3/hcvault`, `github.com/spf13/cobra`, `github.com/stretchr/testify/require`.

## Global Constraints

- Go package: `internal/keyservice/hcvault` (not `vault` — collides with the existing `internal/vault` package). Provider identifier / CLI value: `Name = "vault"`.
- `--key-resource-id` for `--provider vault` is a full Vault Transit key URL: `https://<vault-addr>/v1/<enginePath>/keys/<keyName>` (no version segment — unlike azurekms).
- Parse `--key-resource-id` via sops's own `sopshcvault.NewMasterKeyFromURI`, not a hand-written regex. Guard the empty-string case explicitly first — `NewMasterKeyFromURI("")` returns `(nil, nil)`, which would nil-pointer-dereference downstream if not caught.
- Auth token is never explicitly configured in `.git-vault.yaml` — it's ambient (`VAULT_TOKEN` env, then `~/.vault-token`, both resolved inside sops's `hcvault` package). The `Provider` struct only carries a test-only token override.
- Before every Encrypt/Decrypt call, set `SOPS_HC_VAULT_ALLOWLIST` (constant `sopshcvault.SopsHCVaultAllowlist`) to the parsed key's `VaultAddress`, via `os.Setenv` — pins sops's Vault client to exactly the configured address (its default otherwise allows every host).
- `git vault login`'s fix-it step runs `vault login` with **no arguments** (default token auth method only) — same confirm-then-exec shape as `attemptAzLogin`/`attemptGcloudLogin`/`attemptAWSSSOLogin` in `internal/cli/login.go`, gated by `exec.LookPath("vault")` and `cfg.AutoLogin`.
- Error sentinel name: `hcvault.ErrNoValidToken` (covers missing/invalid/expired token and insufficient ACL policy — Vault returns 403 for all four, indistinguishably; see spec's Non-goals).
- `git vault rotate`'s case for `vault.Name`^[Name] is a plain re-seal (same shape as `awskms.Name`'s case in `rotate.go`) — no config rewrite, since `--key-resource-id` never encodes a version.
- No new third-party dependency: `github.com/hashicorp/vault/api` is already pulled in transitively by the pinned sops version; `go mod tidy` promotes it from indirect to direct.
- Design reference: `docs/superpowers/specs/2026-07-14-vault-provider-design.md`.

---

### Task 1: `hcvaulttest` fake Vault Transit server

**Files:**
- Create: `internal/keyservice/hcvault/hcvaulttest/hcvaulttest.go`
- Test: `internal/keyservice/hcvault/hcvaulttest/hcvaulttest_test.go`

**Interfaces:**
- Produces: `NewFakeServer(expectedToken string) *httptest.Server` — an `httptest.Server` implementing Vault Transit's `PUT /v1/<engine>/encrypt/<key>` and `PUT /v1/<engine>/decrypt/<key>` endpoints. If `expectedToken != ""`, every request must carry `X-Vault-Token: <expectedToken>` (header name: `vaultapi.AuthHeaderName` from `github.com/hashicorp/vault/api`) or the server responds `403` with a Vault-shaped error body (`{"errors": ["permission denied"]}`). If `expectedToken == ""`, the token header is not checked at all (used for tests that only care about the encrypt/decrypt round trip, not auth). The caller must call `.Close()` (e.g. via `defer`).

- [ ] **Step 1: Write the failing test**

```go
// internal/keyservice/hcvault/hcvaulttest/hcvaulttest_test.go
package hcvaulttest

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/require"
)

func TestFakeServer_EncryptDecrypt_RoundTrip(t *testing.T) {
	srv := NewFakeServer("test-token")
	defer srv.Close()

	encBody, err := json.Marshal(map[string]any{"plaintext": "c29wcyBkYXRhIGtleQ=="}) // base64("sops data key")
	require.NoError(t, err)

	var encOut struct {
		Data struct{ Ciphertext string }
	}
	doFakeRequest(t, srv.URL, "test-token", "/v1/transit/encrypt/test-key", encBody, &encOut)
	require.NotEmpty(t, encOut.Data.Ciphertext)

	decBody, err := json.Marshal(map[string]any{"ciphertext": encOut.Data.Ciphertext})
	require.NoError(t, err)

	var decOut struct {
		Data struct{ Plaintext string }
	}
	doFakeRequest(t, srv.URL, "test-token", "/v1/transit/decrypt/test-key", decBody, &decOut)
	require.Equal(t, "c29wcyBkYXRhIGtleQ==", decOut.Data.Plaintext)
}

func TestFakeServer_WrongToken_Returns403(t *testing.T) {
	srv := NewFakeServer("test-token")
	defer srv.Close()

	encBody, err := json.Marshal(map[string]any{"plaintext": "c29wcyBkYXRhIGtleQ=="})
	require.NoError(t, err)

	resp := postFakeRequest(t, srv.URL, "wrong-token", "/v1/transit/encrypt/test-key", encBody)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestFakeServer_Decrypt_TamperedCiphertextFails(t *testing.T) {
	srv := NewFakeServer("")
	defer srv.Close()

	decBody, err := json.Marshal(map[string]any{"ciphertext": "not-a-real-wrapped-key"})
	require.NoError(t, err)

	resp := postFakeRequest(t, srv.URL, "", "/v1/transit/decrypt/test-key", decBody)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func postFakeRequest(t *testing.T, baseURL, token, path string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, baseURL+path, bytes.NewReader(body))
	require.NoError(t, err)
	if token != "" {
		req.Header.Set(vaultapi.AuthHeaderName, token)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

func doFakeRequest(t *testing.T, baseURL, token, path string, body []byte, out any) {
	t.Helper()
	resp := postFakeRequest(t, baseURL, token, path, body)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, out))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/keyservice/hcvault/hcvaulttest/... -run TestFakeServer -v`
Expected: FAIL — `undefined: NewFakeServer` (package doesn't exist yet).

- [ ] **Step 3: Write the fake server implementation**

```go
// internal/keyservice/hcvault/hcvaulttest/hcvaulttest.go

// Package hcvaulttest provides a fake HashiCorp Vault Transit server for
// testing code that uses internal/keyservice/hcvault's Provider, without a
// real Vault cluster. Unlike azurekmstest/awskmstest (which need a
// redirect transport because their SDK resolves a fixed cloud host), sops's
// hcvault.MasterKey is constructed directly from the --key-resource-id URL
// (via NewMasterKeyFromURI), so pointing that URL at this server's real
// httptest.Server address is enough — no custom http.Client override
// needed.
package hcvaulttest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"

	vaultapi "github.com/hashicorp/vault/api"
)

// marker prefixes every "ciphertext" this fake server produces, and is
// stripped back off on Decrypt — enough to prove real data flows through
// sops's hcvault.MasterKey end-to-end without performing real cryptography
// or touching a real Vault cluster.
const marker = "fake-transit-wrapped:"

type encryptRequest struct {
	Plaintext string `json:"plaintext"`
}

type decryptRequest struct {
	Ciphertext string `json:"ciphertext"`
}

// NewFakeServer starts a fake Vault Transit HTTP server on a random local
// port. If expectedToken is non-empty, every request must carry an
// X-Vault-Token header matching it, or the server responds 403 (Vault's
// real permission-denied status for a missing/invalid/expired token). The
// caller must call the returned server's Close (e.g. via defer).
func NewFakeServer(expectedToken string) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/transit/encrypt/", func(w http.ResponseWriter, r *http.Request) {
		if !tokenOK(w, r, expectedToken) {
			return
		}
		var req encryptRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeVaultError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeVaultData(w, map[string]any{"ciphertext": marker + req.Plaintext})
	})
	mux.HandleFunc("/v1/transit/decrypt/", func(w http.ResponseWriter, r *http.Request) {
		if !tokenOK(w, r, expectedToken) {
			return
		}
		var req decryptRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeVaultError(w, http.StatusBadRequest, err.Error())
			return
		}
		if !strings.HasPrefix(req.Ciphertext, marker) {
			writeVaultError(w, http.StatusBadRequest, "hcvaulttest: ciphertext missing fake marker")
			return
		}
		writeVaultData(w, map[string]any{"plaintext": strings.TrimPrefix(req.Ciphertext, marker)})
	})
	return httptest.NewServer(mux)
}

func tokenOK(w http.ResponseWriter, r *http.Request, expectedToken string) bool {
	if expectedToken == "" || r.Header.Get(vaultapi.AuthHeaderName) == expectedToken {
		return true
	}
	writeVaultError(w, http.StatusForbidden, "permission denied")
	return false
}

func writeVaultData(w http.ResponseWriter, data map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
}

func writeVaultError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{msg}})
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/keyservice/hcvault/hcvaulttest/... -v`
Expected: PASS (all three tests).

- [ ] **Step 5: Commit**

```bash
git add internal/keyservice/hcvault/hcvaulttest/
git commit -m "test(hcvault): add fake Vault Transit server for provider tests"
```

---

### Task 2: `hcvault.Provider`

**Files:**
- Create: `internal/keyservice/hcvault/hcvault.go`
- Test: `internal/keyservice/hcvault/hcvault_test.go`

**Interfaces:**
- Consumes: `hcvaulttest.NewFakeServer(expectedToken string) *httptest.Server` (Task 1).
- Produces:
  - `const Name = "vault"`
  - `func SetTestOverridesForTesting(token string) (restore func())`
  - `type Provider struct{ token string }`
  - `func New() Provider`
  - `func (p Provider) Name() string`
  - `func (p Provider) Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error)`
  - `func (p Provider) Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error)`
  - `var ErrNoValidToken = errors.New(...)`
  - `func friendlyLoginErr(op string, err error) error` (package-private, used by Encrypt/Decrypt)

- [ ] **Step 1: Write the failing test**

```go
// internal/keyservice/hcvault/hcvault_test.go
package hcvault

import (
	"context"
	"errors"
	"fmt"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/require"

	"github.com/ducduyn31/git-vault/internal/keyservice/hcvault/hcvaulttest"
)

func TestProvider_EncryptDecrypt_RoundTrip(t *testing.T) {
	srv := hcvaulttest.NewFakeServer("test-token")
	defer srv.Close()
	restore := SetTestOverridesForTesting("test-token")
	defer restore()

	keyID := srv.URL + "/v1/transit/keys/test-key"
	p := New()
	require.Equal(t, Name, p.Name())

	ciphertext, err := p.Encrypt(context.Background(), keyID, []byte("sops data key"))
	require.NoError(t, err)
	require.NotEqual(t, "sops data key", string(ciphertext))

	plaintext, err := p.Decrypt(context.Background(), keyID, ciphertext)
	require.NoError(t, err)
	require.Equal(t, "sops data key", string(plaintext))
}

func TestProvider_Decrypt_TamperedCiphertextFails(t *testing.T) {
	srv := hcvaulttest.NewFakeServer("")
	defer srv.Close()
	restore := SetTestOverridesForTesting("")
	defer restore()

	keyID := srv.URL + "/v1/transit/keys/test-key"
	p := New()
	_, err := p.Decrypt(context.Background(), keyID, []byte("not a real wrapped key"))
	require.Error(t, err)
}

func TestProvider_Encrypt_EmptyKeyIDFails(t *testing.T) {
	p := New()
	_, err := p.Encrypt(context.Background(), "", []byte("data"))
	require.ErrorContains(t, err, "key ID is required")
}

func TestProvider_Encrypt_MalformedURLFails(t *testing.T) {
	p := New()
	_, err := p.Encrypt(context.Background(), "not-a-url", []byte("data"))
	require.Error(t, err)
}

func TestProvider_Encrypt_WrongTokenFails(t *testing.T) {
	srv := hcvaulttest.NewFakeServer("expected-token")
	defer srv.Close()
	restore := SetTestOverridesForTesting("wrong-token")
	defer restore()

	keyID := srv.URL + "/v1/transit/keys/test-key"
	p := New()
	_, err := p.Encrypt(context.Background(), keyID, []byte("data"))
	require.ErrorIs(t, err, ErrNoValidToken)
}

func TestFriendlyLoginErr_RewritesPermissionDenied(t *testing.T) {
	// Wrapped with %w the same way sops's hcvault package wraps it
	// ("failed to encrypt sops data key to Vault transit backend '%s': %w"),
	// so this exercises the same errors.As unwrapping friendlyLoginErr relies on.
	respErr := &vaultapi.ResponseError{StatusCode: 403, Errors: []string{"permission denied"}}
	wrapped := fmt.Errorf("failed to encrypt sops data key to Vault transit backend 'transit/encrypt/test-key': %w", respErr)

	err := friendlyLoginErr("encrypt", wrapped)
	require.ErrorIs(t, err, ErrNoValidToken)
}

func TestFriendlyLoginErr_PassesThroughOtherErrors(t *testing.T) {
	err := friendlyLoginErr("encrypt", errors.New("network unreachable"))
	require.ErrorContains(t, err, "hcvault: encrypt: network unreachable")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/keyservice/hcvault/... -run TestProvider -v`
Expected: FAIL — `undefined: SetTestOverridesForTesting` / `undefined: New` (package doesn't exist yet).

- [ ] **Step 3: Write the minimal implementation**

```go
// internal/keyservice/hcvault/hcvault.go

// Package hcvault implements a keyservice.Provider backed by HashiCorp
// Vault's Transit secrets engine, authorized via whatever bearer token
// sops's own hcvault package resolves on this machine (the VAULT_TOKEN
// env var, then ~/.vault-token — the file the `vault` CLI's `vault login`
// writes). Unlike internal/keyservice/local and .../passphrase, git-vault
// holds no key material of its own here: Vault's ACL policy on the
// Transit key is the only access control, and git-vault never implements
// its own auth flow — `git vault login` (internal/cli/login.go) only ever
// shells out to the real `vault login`, and only with the user's explicit
// confirmation (or config.Config.AutoLogin). See
// docs/superpowers/specs/2026-07-14-vault-provider-design.md.
package hcvault

import (
	"context"
	"errors"
	"fmt"
	"os"

	sopshcvault "github.com/getsops/sops/v3/hcvault"
	vaultapi "github.com/hashicorp/vault/api"
)

// Name is the provider name used in "vault:<key-url>" key identifiers
// (see internal/keyservice.Server).
const Name = "vault"

// testToken overrides the token every MasterKey this package's Providers
// create authenticates with. Set only via SetTestOverridesForTesting.
var testToken string

// SetTestOverridesForTesting points every Provider subsequently created
// by New at a fixed token instead of the real VAULT_TOKEN/~/.vault-token
// resolution, so tests can run against a fake server (see hcvaulttest)
// without real Vault credentials. It returns a function that restores the
// previous override — call it via defer. For use in tests only.
func SetTestOverridesForTesting(token string) (restore func()) {
	prev := testToken
	testToken = token
	return func() { testToken = prev }
}

// Provider is backed by a Vault Transit key, identified per-call by keyID
// (a full Transit key URL) rather than fixed at construction — the URL
// lives in git-vault's repo-tracked config
// (internal/config.Config.KeyResourceID), not in this Provider.
type Provider struct {
	token string
}

// New returns a Provider using real Vault token resolution, unless
// SetTestOverridesForTesting has redirected it to a fixed test token.
func New() Provider {
	return Provider{token: testToken}
}

func (p Provider) Name() string { return Name }

// Encrypt wraps plaintext (a sops data key) with the Vault Transit key
// named by keyID (a URL of the form
// https://<vault-addr>/v1/<enginePath>/keys/<keyName>).
func (p Provider) Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error) {
	key, err := p.parseKeyID(keyID)
	if err != nil {
		return nil, err
	}
	if err := key.EncryptContext(ctx, plaintext); err != nil {
		return nil, friendlyLoginErr("encrypt", err)
	}
	return key.EncryptedDataKey(), nil
}

// Decrypt unwraps ciphertext (see Encrypt) with the Vault Transit key
// named by keyID.
func (p Provider) Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error) {
	key, err := p.parseKeyID(keyID)
	if err != nil {
		return nil, err
	}
	key.SetEncryptedDataKey(ciphertext)
	plaintext, err := key.DecryptContext(ctx)
	if err != nil {
		return nil, friendlyLoginErr("decrypt", err)
	}
	return plaintext, nil
}

// parseKeyID builds a sops hcvault.MasterKey from keyID, applies this
// Provider's test token override (if any), and pins
// SOPS_HC_VAULT_ALLOWLIST to the key's parsed VaultAddress so sops's
// client only ever talks to the configured Vault, not whatever the
// ambient environment might otherwise allow (its default is "allow every
// host").
func (p Provider) parseKeyID(keyID string) (*sopshcvault.MasterKey, error) {
	if keyID == "" {
		return nil, errors.New("hcvault: key ID is required (a Vault Transit key URL)")
	}
	key, err := sopshcvault.NewMasterKeyFromURI(keyID)
	if err != nil {
		return nil, fmt.Errorf("hcvault: %w", err)
	}
	_ = os.Setenv(sopshcvault.SopsHCVaultAllowlist, key.VaultAddress)
	if p.token != "" {
		sopshcvault.Token(p.token).ApplyToMasterKey(key)
	}
	return key, nil
}

// ErrNoValidToken is returned (via friendlyLoginErr) when Vault responds
// with 403 permission denied — Vault's single status for a missing,
// invalid, or expired token, or a valid token lacking the right ACL
// policy. It's a sentinel rather than just a message so callers — namely
// internal/cli/login.go — can detect this specific, fixable case with
// errors.Is and offer to run `vault login` themselves, instead of every
// caller re-parsing error text.
var ErrNoValidToken = errors.New("hcvault: no valid Vault token — run `vault login` first")

// friendlyLoginErr rewrites a Vault 403 response into ErrNoValidToken.
// Any other error (network failure, sealed vault, malformed key path) is
// wrapped with op but otherwise passed through as-is.
func friendlyLoginErr(op string, err error) error {
	var respErr *vaultapi.ResponseError
	if errors.As(err, &respErr) && respErr.StatusCode == 403 {
		return ErrNoValidToken
	}
	return fmt.Errorf("hcvault: %s: %w", op, err)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/keyservice/hcvault/... -v`
Expected: PASS (all seven tests in `hcvault_test.go`, plus the three from Task 1).

- [ ] **Step 5: Commit**

```bash
git add internal/keyservice/hcvault/hcvault.go internal/keyservice/hcvault/hcvault_test.go
git commit -m "feat(hcvault): add Vault Transit keyservice.Provider"
```

---

### Task 3: Wire `hcvault` into `internal/cli/vault.go`

**Files:**
- Modify: `internal/cli/vault.go` (add import, `newHCVaultVault`, and a `case` in `vaultForProvider`)
- Test: `internal/cli/vault_test.go`

**Interfaces:**
- Consumes: `hcvault.Name`, `hcvault.New()`, `hcvault.SetTestOverridesForTesting` (Task 2); `hcvaulttest.NewFakeServer` (Task 1); `keyservice.NewRegistry()`, `keyservice.NewServer(*Registry)`, `vault.New(*keyservice.Server) *vault.Vault` (existing).
- Produces: `func newHCVaultVault(cfg config.Config) (*vault.Vault, []string, error)`, and `vaultForProvider` now recognizes `hcvault.Name`.

- [ ] **Step 1: Write the failing test**

Add to `internal/cli/vault_test.go` (mirroring its existing azurekms case at line 71):

```go
func TestVaultForProvider_HCVault_ResolvesRecipient(t *testing.T) {
	srv := hcvaulttest.NewFakeServer("")
	defer srv.Close()
	restore := hcvault.SetTestOverridesForTesting("")
	defer restore()

	keyID := srv.URL + "/v1/transit/keys/test-key"
	_, recipients, err := vaultForProvider(config.Config{
		Provider:      hcvault.Name,
		KeyResourceID: keyID,
	})
	require.NoError(t, err)
	require.Equal(t, []string{"vault:" + keyID}, recipients)
}
```

Add the two new imports next to the existing `azurekms`/`azurekmstest` ones:

```go
	"github.com/ducduyn31/git-vault/internal/keyservice/hcvault"
	"github.com/ducduyn31/git-vault/internal/keyservice/hcvault/hcvaulttest"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cli/... -run TestVaultForProvider_HCVault -v`
Expected: FAIL — `undefined: hcvault` (not imported/wired into `vault.go` yet).

- [ ] **Step 3: Wire it into `internal/cli/vault.go`**

Add the import (alongside the existing `azurekms` import at line 11):

```go
	"github.com/ducduyn31/git-vault/internal/keyservice/hcvault"
```

Add this function after `newAzureKMSVault` (after line 102):

```go
// newHCVaultVault builds a Vault dispatching to HashiCorp Vault's Transit
// engine, along with the "<provider>:<key-id>" recipient string for
// cfg.KeyResourceID (a Vault Transit key URL). Unlike local/passphrase,
// the key material lives entirely in Vault — this Provider holds no
// identity of its own beyond whatever bearer token VAULT_TOKEN/
// ~/.vault-token resolves to.
func newHCVaultVault(cfg config.Config) (*vault.Vault, []string, error) {
	registry := keyservice.NewRegistry()
	if err := registry.Register(hcvault.New()); err != nil {
		return nil, nil, err
	}
	server := keyservice.NewServer(registry)

	return vault.New(server), []string{hcvault.Name + ":" + cfg.KeyResourceID}, nil
}
```

Add a case to `vaultForProvider`'s switch (after the `azurekms.Name` case at line 119):

```go
	case hcvault.Name:
		return newHCVaultVault(cfg)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/cli/... -run TestVaultForProvider_HCVault -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/vault.go internal/cli/vault_test.go
git commit -m "feat(cli): wire hcvault provider into vaultForProvider"
```

---

### Task 4: `git vault install --provider vault`

**Files:**
- Modify: `internal/cli/install.go`
- Test: `internal/cli/install_test.go`

**Interfaces:**
- Consumes: `hcvault.Name`, `hcvault.New()`, `hcvault.ErrNoValidToken`, `hcvault.SetTestOverridesForTesting` (Task 2); `newHCVaultVault`/`vaultForProvider` (Task 3); `verifyVaultRoundTrip`/`attemptVaultLogin` (Task 5 — see note below).
- Produces: `install --provider vault --key-resource-id <url>` writes `.git-vault.yaml` and validates the key with a real round trip, same as the other three KMS-style providers.

> **Note on task ordering:** This task's `install.go` change calls `verifyVaultRoundTrip`/`attemptVaultLogin`, which Task 5 adds to `login.go`. Since both files are in package `cli`, do Task 5's `login.go` additions **first** (just the two functions — do not wire `login.go`'s command switch yet), then come back to this task, then finish Task 5's command-switch wiring. To keep this plan's tasks independently reviewable in order, this task includes the full `verifyVaultRoundTrip`/`attemptVaultLogin` code inline (Task 5 will find them already present and only add the `login` command's `case` and its own tests).

- [ ] **Step 1: Write the failing tests**

Add to `internal/cli/install_test.go` (mirroring the existing `TestInstallCmd_AzureKMS_*` tests at lines 328–376):

```go
func TestInstallCmd_Vault_WritesConfigAndValidates(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	srv := hcvaulttest.NewFakeServer("")
	defer srv.Close()
	restore := hcvault.SetTestOverridesForTesting("")
	defer restore()

	keyID := srv.URL + "/v1/transit/keys/test-key"
	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{
		"install", "--provider=" + hcvault.Name,
		"--key-resource-id=" + keyID,
	})
	require.NoError(t, cmd.Execute())

	require.Contains(t, out.String(), "Recipient: vault:"+keyID)

	cfg, err := config.Load(config.DefaultFileName)
	require.NoError(t, err)
	require.Equal(t, hcvault.Name, cfg.Provider)
	require.Equal(t, keyID, cfg.KeyResourceID)
}

func TestInstallCmd_Vault_MissingKeyResourceIDFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"install", "--provider=" + hcvault.Name})

	err := cmd.Execute()
	require.ErrorContains(t, err, "--key-resource-id is required")
}

func TestInstallCmd_Vault_FailsWithoutReachableVault(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"install", "--provider=" + hcvault.Name,
		"--key-resource-id=not-a-valid-url",
	})

	err := cmd.Execute()
	require.Error(t, err)

	_, gitErr := exec.Command("git", "config", "--get", "filter.git-vault.clean").Output()
	require.Error(t, gitErr, "git config must not be set when install fails the Vault round trip")
}
```

Add the two new imports next to the existing `azurekms`/`azurekmstest` ones at the top of `install_test.go`:

```go
	"github.com/ducduyn31/git-vault/internal/keyservice/hcvault"
	"github.com/ducduyn31/git-vault/internal/keyservice/hcvault/hcvaulttest"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cli/... -run TestInstallCmd_Vault -v`
Expected: FAIL — `--provider vault` isn't recognized by `vaultForProvider` for `install`'s purposes yet (the `--key-resource-id is required` check and the round-trip switch in `install.go` don't know about it).

- [ ] **Step 3: First, add the two round-trip/login-fix functions to `internal/cli/login.go`**

Add this import to `login.go`'s import block (alongside `azurekms`):

```go
	"github.com/ducduyn31/git-vault/internal/keyservice/hcvault"
```

Add these two functions after `attemptAzLogin` (after line 155 in the file as read):

```go
// attemptVaultLogin tries to fix a permission-denied failure
// (hcvault.ErrNoValidToken) by running `vault login` with no arguments —
// the default token auth method. Mirrors attemptAzLogin's
// confirm-before-exec shape exactly, including the autoLogin
// (config.Config.AutoLogin) opt-out. Orgs using a non-default auth method
// (OIDC, LDAP, GitHub, AppRole) should run their own
// `vault login -method=...` first; this only covers the common case.
func attemptVaultLogin(cmd *cobra.Command, autoLogin bool) bool {
	path, err := exec.LookPath("vault")
	if err != nil {
		return false
	}

	if !autoLogin {
		if _, err := fmt.Fprint(cmd.OutOrStdout(), "No valid Vault token found. Run `vault login` now? [y/N] "); err != nil {
			return false
		}
		line, _ := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
		if answer := strings.ToLower(strings.TrimSpace(line)); answer != "y" && answer != "yes" {
			return false
		}
	}

	vaultCmd := exec.CommandContext(cmd.Context(), path, "login")
	vaultCmd.Stdin = cmd.InOrStdin()
	vaultCmd.Stdout = cmd.OutOrStdout()
	vaultCmd.Stderr = cmd.ErrOrStderr()
	return vaultCmd.Run() == nil
}

// verifyVaultRoundTrip is verifyGCPKMSRoundTrip's Vault Transit
// equivalent — see its doc comment.
func verifyVaultRoundTrip(ctx context.Context, keyResourceID string) error {
	provider := hcvault.New()
	ciphertext, err := provider.Encrypt(ctx, keyResourceID, []byte(loginProbe))
	if err != nil {
		return err
	}
	plaintext, err := provider.Decrypt(ctx, keyResourceID, ciphertext)
	if err != nil {
		return err
	}
	if string(plaintext) != loginProbe {
		return fmt.Errorf("hcvault: round trip returned unexpected plaintext")
	}
	return nil
}
```

(Do **not** add a `case hcvault.Name` to `newLoginCmd`'s switch yet — that's Task 5's job, together with its own tests. Adding it here without also adding those tests would violate this plan's "every step ends with a passing test" rule.)

- [ ] **Step 4: Wire `vault` into `internal/cli/install.go`**

Add the import (alongside `azurekms` at line 12):

```go
	"github.com/ducduyn31/git-vault/internal/keyservice/hcvault"
```

Change the "resource ID required" condition (line 45):

```go
			if (providerName == gcpkms.Name || providerName == awskms.Name || providerName == azurekms.Name || providerName == hcvault.Name) && keyResourceID == "" {
```

Add a case to the round-trip switch (after the `azurekms.Name` case, i.e. after line 80):

```go
			case hcvault.Name:
				err := verifyVaultRoundTrip(cmd.Context(), keyResourceID)
				if errors.Is(err, hcvault.ErrNoValidToken) && attemptVaultLogin(cmd, autoLogin) {
					err = verifyVaultRoundTrip(cmd.Context(), keyResourceID)
				}
				if err != nil {
					return fmt.Errorf("git vault install: %w", err)
				}
```

Update the two flag help strings (lines 108–109):

```go
	cmd.Flags().String("provider", local.Name, "key provider to use (local, passphrase, gcpkms, awskms, azurekms, vault)")
	cmd.Flags().String("key-resource-id", "", "GCP KMS resource ID, AWS KMS ARN, Azure Key Vault key URL, or Vault Transit key URL (required when --provider gcpkms, awskms, azurekms, or vault)")
```

Update the `--auto-login` flag help string (line 111) to add `vault`:

```go
	cmd.Flags().Bool("auto-login", false, "skip the confirmation prompt and run the provider's login command automatically when credentials are missing (gcpkms, awskms, azurekms, vault)")
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/cli/... -run TestInstallCmd_Vault -v`
Expected: PASS (all three tests).

Run the full package too, to confirm nothing else broke:

Run: `go test ./internal/cli/... -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/cli/install.go internal/cli/install_test.go internal/cli/login.go
git commit -m "feat(cli): support --provider vault in git vault install"
```

---

### Task 5: `git vault login` for `vault`

**Files:**
- Modify: `internal/cli/login.go` (add the `case hcvault.Name` to `newLoginCmd`'s switch — the two helper functions already exist from Task 4)
- Test: `internal/cli/login_test.go`

**Interfaces:**
- Consumes: `hcvault.Name`, `hcvault.ErrNoValidToken`, `hcvault.SetTestOverridesForTesting` (Task 2); `hcvaulttest.NewFakeServer` (Task 1); `verifyVaultRoundTrip`/`attemptVaultLogin` (added in Task 4, Step 3); `promptCmd` (existing test helper in `login_test.go`).
- Produces: `git vault login` succeeds/fails correctly for `Provider: hcvault.Name`, and offers to run `vault login` on a permission-denied failure.

- [ ] **Step 1: Write the failing tests**

Add to `internal/cli/login_test.go` (mirroring the existing `TestLoginCmd_AzureKMS_*` tests):

```go
func TestLoginCmd_Vault_Succeeds(t *testing.T) {
	chdirTemp(t)

	srv := hcvaulttest.NewFakeServer("")
	defer srv.Close()
	restore := hcvault.SetTestOverridesForTesting("")
	defer restore()

	keyID := srv.URL + "/v1/transit/keys/test-key"
	require.NoError(t, config.Save(config.DefaultFileName, config.Config{
		Provider:      hcvault.Name,
		KeyResourceID: keyID,
	}))

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{"login"})
	require.NoError(t, cmd.Execute())
	require.Contains(t, out.String(), "authorized")
}

func TestLoginCmd_Vault_FailsWithoutReachableVault(t *testing.T) {
	chdirTemp(t)
	require.NoError(t, config.Save(config.DefaultFileName, config.Config{
		Provider:      hcvault.Name,
		KeyResourceID: "not-a-valid-url",
	}))

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"login"})
	require.Error(t, cmd.Execute())
}

func fakeVaultCLI(t *testing.T, exitCode int) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake vault script assumes a POSIX shell")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "vault")
	contents := fmt.Sprintf("#!/bin/sh\nexit %d\n", exitCode)
	require.NoError(t, os.WriteFile(script, []byte(contents), 0o755))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestAttemptVaultLogin_NoVaultCLIOnPath(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	out := &bytes.Buffer{}
	require.False(t, attemptVaultLogin(promptCmd(bytes.NewBufferString("y\n"), out), false))
	require.Empty(t, out.String())
}

func TestAttemptVaultLogin_Declined(t *testing.T) {
	fakeVaultCLI(t, 0)
	out := &bytes.Buffer{}
	require.False(t, attemptVaultLogin(promptCmd(bytes.NewBufferString("n\n"), out), false))
	require.Contains(t, out.String(), "Run `vault login` now?")
}

func TestAttemptVaultLogin_ConfirmedAndCLISucceeds(t *testing.T) {
	fakeVaultCLI(t, 0)
	out := &bytes.Buffer{}
	require.True(t, attemptVaultLogin(promptCmd(bytes.NewBufferString("y\n"), out), false))
}

func TestAttemptVaultLogin_ConfirmedButCLIFails(t *testing.T) {
	fakeVaultCLI(t, 1)
	out := &bytes.Buffer{}
	require.False(t, attemptVaultLogin(promptCmd(bytes.NewBufferString("yes\n"), out), false))
}

func TestAttemptVaultLogin_AutoLoginSkipsPrompt(t *testing.T) {
	fakeVaultCLI(t, 0)
	out := &bytes.Buffer{}
	require.True(t, attemptVaultLogin(promptCmd(bytes.NewBufferString(""), out), true))
	require.Empty(t, out.String())
}
```

Add the two new imports next to the existing `azurekms`/`azurekmstest` ones at the top of `login_test.go` (check first whether `runtime`, `os`, `filepath`, `fmt` are already imported — they are, since `fakeAzCLI` already uses all four):

```go
	"github.com/ducduyn31/git-vault/internal/keyservice/hcvault"
	"github.com/ducduyn31/git-vault/internal/keyservice/hcvault/hcvaulttest"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cli/... -run 'TestLoginCmd_Vault|TestAttemptVaultLogin' -v`
Expected: FAIL — `TestLoginCmd_Vault_*` fail with `provider "vault" does not use git vault login` (no `case hcvault.Name` yet); `TestAttemptVaultLogin_*` pass already (the function exists from Task 4) — confirm this split explicitly when you run it.

- [ ] **Step 3: Add the case to `newLoginCmd`'s switch in `internal/cli/login.go`**

Add after the `azurekms.Name` case (after line 62, before `default:`):

```go
			case hcvault.Name:
				err = verifyVaultRoundTrip(cmd.Context(), cfg.KeyResourceID)
				if errors.Is(err, hcvault.ErrNoValidToken) && attemptVaultLogin(cmd, cfg.AutoLogin) {
					err = verifyVaultRoundTrip(cmd.Context(), cfg.KeyResourceID)
				}
				if err != nil {
					return fmt.Errorf("git vault login: %w", err)
				}
				_, err = fmt.Fprintln(cmd.OutOrStdout(), "Vault Transit round trip succeeded — this machine is authorized.")
				return err
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/cli/... -run 'TestLoginCmd_Vault|TestAttemptVaultLogin' -v`
Expected: PASS (all 7 tests).

Run the full package: `go test ./internal/cli/... -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/login.go internal/cli/login_test.go
git commit -m "feat(cli): support git vault login for --provider vault"
```

---

### Task 6: `git vault rotate` for `vault`

**Files:**
- Modify: `internal/cli/rotate.go`
- Test: `internal/cli/rotate_test.go`

**Interfaces:**
- Consumes: `hcvault.Name` (Task 2); `vaultForProvider` (Task 3); `setupTrackedEncryptedFileWithConfig` (existing test helper in `install_test.go`).
- Produces: `git vault rotate` re-seals every tracked file for `Provider: hcvault.Name`, with no `.git-vault.yaml` rewrite.

- [ ] **Step 1: Write the failing test**

Add to `internal/cli/rotate_test.go` (mirroring an AWS-KMS-shaped rotate test — plain re-seal, no version re-resolution):

```go
func TestRotateCmd_Vault_RoundTrips(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	srv := hcvaulttest.NewFakeServer("")
	defer srv.Close()
	restore := hcvault.SetTestOverridesForTesting("")
	defer restore()

	keyID := srv.URL + "/v1/transit/keys/test-key"
	original := setupTrackedEncryptedFileWithConfig(t, config.Config{
		Provider:      hcvault.Name,
		KeyResourceID: keyID,
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
	require.NotEqual(t, string(sealedBefore), string(sealedAfter), "rotate must force a fresh Vault Encrypt call")

	cfg, err := config.Load(config.DefaultFileName)
	require.NoError(t, err)
	require.Equal(t, keyID, cfg.KeyResourceID, "vault's key URL never encodes a version, so rotate must not rewrite it")

	decryptCmd := NewRootCmd()
	decryptCmd.SetOut(&bytes.Buffer{})
	decryptCmd.SetArgs([]string{"decrypt", "secret.yaml"})
	require.NoError(t, decryptCmd.Execute())

	opened, err := os.ReadFile("secret.yaml")
	require.NoError(t, err)
	require.Equal(t, original, string(opened))
}
```

Add the two new imports next to the existing `azurekms`/`azurekmstest` ones at the top of `rotate_test.go`:

```go
	"github.com/ducduyn31/git-vault/internal/keyservice/hcvault"
	"github.com/ducduyn31/git-vault/internal/keyservice/hcvault/hcvaulttest"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cli/... -run TestRotateCmd_Vault -v`
Expected: FAIL — `git vault rotate: rotation not supported for provider "vault"` (no `case hcvault.Name` in `rotate.go`'s switch yet).

- [ ] **Step 3: Add the case to `internal/cli/rotate.go`**

Add the import (alongside `azurekms`):

```go
	"github.com/ducduyn31/git-vault/internal/keyservice/hcvault"
```

Add a case after `awskms.Name`'s (after line 91, before `case azurekms.Name:`):

```go
			case hcvault.Name:
				// The Transit key URL never encodes a version (unlike
				// azurekms's Key Vault URL), and Vault Transit rotation
				// (vault write -f transit/keys/<name>/rotate) is
				// invisible to git-vault the same way GCP's and AWS's
				// automatic rotation are — there is no "current version"
				// to re-resolve and persist. Re-sealing every file still
				// forces a fresh Encrypt call, which Vault always
				// services with the key's current version.
				newVault, newRecipients, err = vaultForProvider(cfg)
				if err != nil {
					return fmt.Errorf("git vault rotate: %w", err)
				}
				oldVault = newVault
```

Add a follow-up message case (alongside the existing `switch cfg.Provider` block for `followUp`, after the `awskms.Name` case):

```go
			case hcvault.Name:
				followUp = "Vault Transit key versions are still enabled to decrypt anything not yet migrated, including committed history (governed by the key's min_decryption_version). Once every commit that matters has been rotated, run `vault write transit/keys/<name>/config min_decryption_version=<new-version>` to retire the old version(s)."
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/cli/... -run TestRotateCmd_Vault -v`
Expected: PASS.

Run the full package: `go test ./internal/cli/... -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/rotate.go internal/cli/rotate_test.go
git commit -m "feat(cli): support git vault rotate for --provider vault"
```

---

### Task 7: `git vault migrate` for/to `vault`

**Files:**
- Modify: `internal/cli/migrate.go`
- Test: `internal/cli/migrate_test.go`

**Interfaces:**
- Consumes: `hcvault.Name`, `hcvault.SetTestOverridesForTesting` (Task 2); `verifyVaultRoundTrip` (Task 4); `vaultForProvider` (Task 3); `setupTrackedEncryptedFile`/`setupTrackedEncryptedFileWithConfig` (existing test helpers).
- Produces: `git vault migrate --provider vault ...` (migrating *to* Vault) and migrating *from* an existing `vault` config both work, with the same identical-target rejection and fail-fast-before-resealing behavior every other provider gets.

- [ ] **Step 1: Write the failing tests**

Add to `internal/cli/migrate_test.go` (mirroring `TestMigrateCmd_AWSKMSToAWSKMS_DifferentKey_RoundTrip` and the `AzureKMSTarget_MissingKeyResourceIDFails`/`UnreachableKeyFailsBeforeResealing` shapes):

```go
func TestMigrateCmd_LocalToVault_RoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	original := setupTrackedEncryptedFile(t, local.Name)

	srv := hcvaulttest.NewFakeServer("")
	defer srv.Close()
	restore := hcvault.SetTestOverridesForTesting("")
	defer restore()

	keyID := srv.URL + "/v1/transit/keys/test-key"
	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{
		"migrate", "--provider=" + hcvault.Name,
		"--key-resource-id=" + keyID,
	})
	require.NoError(t, cmd.Execute())
	require.Contains(t, out.String(), "Migrated 1 file")

	cfg, err := config.Load(config.DefaultFileName)
	require.NoError(t, err)
	require.Equal(t, hcvault.Name, cfg.Provider)
	require.Equal(t, keyID, cfg.KeyResourceID)

	decryptCmd := NewRootCmd()
	decryptCmd.SetOut(&bytes.Buffer{})
	decryptCmd.SetArgs([]string{"decrypt", "secret.yaml"})
	require.NoError(t, decryptCmd.Execute())

	opened, err := os.ReadFile("secret.yaml")
	require.NoError(t, err)
	require.Equal(t, original, string(opened))
}

func TestMigrateCmd_VaultTarget_MissingKeyResourceIDFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	setupTrackedEncryptedFile(t, local.Name)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"migrate", "--provider=" + hcvault.Name})

	err := cmd.Execute()
	require.ErrorContains(t, err, "--key-resource-id is required")
}

func TestMigrateCmd_VaultTarget_UnreachableKeyFailsBeforeResealing(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	setupTrackedEncryptedFile(t, local.Name)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"migrate", "--provider=" + hcvault.Name,
		"--key-resource-id=not-a-valid-url",
	})

	err := cmd.Execute()
	require.Error(t, err)

	cfg, err := config.Load(config.DefaultFileName)
	require.NoError(t, err)
	require.Equal(t, local.Name, cfg.Provider, ".git-vault.yaml must be untouched when the target key is unreachable")
}
```

Add the two new imports next to the existing `azurekms`/`azurekmstest` ones at the top of `migrate_test.go`:

```go
	"github.com/ducduyn31/git-vault/internal/keyservice/hcvault"
	"github.com/ducduyn31/git-vault/internal/keyservice/hcvault/hcvaulttest"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cli/... -run TestMigrateCmd_.*Vault -v`
Expected: FAIL — `--key-resource-id is required` check doesn't recognize `hcvault.Name` yet, and there's no round-trip verification case for it.

- [ ] **Step 3: Wire `vault` into `internal/cli/migrate.go`**

Add the import (alongside `azurekms` at line 10):

```go
	"github.com/ducduyn31/git-vault/internal/keyservice/hcvault"
```

Update the resource-ID-required condition (line 53):

```go
			if (target == gcpkms.Name || target == awskms.Name || target == azurekms.Name || target == hcvault.Name) && keyResourceID == "" {
```

Add a case to the round-trip switch (after the `azurekms.Name` case, i.e. after line 96):

```go
			case hcvault.Name:
				if err := verifyVaultRoundTrip(cmd.Context(), keyResourceID); err != nil {
					return fmt.Errorf("git vault migrate: %w", err)
				}
```

Update the two flag help strings (lines 115–116):

```go
	cmd.Flags().String("provider", "", "target key provider to migrate to (local, passphrase, gcpkms, awskms, azurekms, vault)")
	cmd.Flags().String("key-resource-id", "", "GCP KMS resource ID, AWS KMS ARN, Azure Key Vault key URL, or Vault Transit key URL (required when --provider gcpkms, awskms, azurekms, or vault)")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/cli/... -run TestMigrateCmd_.*Vault -v`
Expected: PASS (all three tests).

Run the full package: `go test ./internal/cli/... -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/migrate.go internal/cli/migrate_test.go
git commit -m "feat(cli): support git vault migrate for --provider vault"
```

---

### Task 8: Docs + `go.mod tidy`

**Files:**
- Create: `docs/vault-provider.md`
- Modify: `README.md`
- Modify: `go.mod`, `go.sum` (via `go mod tidy`)

**Interfaces:**
- None — this task is documentation and dependency bookkeeping, no new Go symbols.

- [ ] **Step 1: Write `docs/vault-provider.md`**

```markdown
# HashiCorp Vault provider

git-vault's `vault` provider authorizes encrypt/decrypt through a
HashiCorp Vault Transit key, using whatever bearer token is already
active on your machine: the `VAULT_TOKEN` environment variable, falling
back to `~/.vault-token` (the file the `vault` CLI's `vault login` writes).

## 1. Admin bootstrap (one-time, done by whoever administers the Vault cluster)

    vault secrets enable transit
    vault write -f transit/keys/git-vault-key

    vault policy write git-vault-key - <<EOF
    path "transit/encrypt/git-vault-key" {
      capabilities = ["update"]
    }
    path "transit/decrypt/git-vault-key" {
      capabilities = ["update"]
    }
    EOF

Grant that policy to whichever auth method your team logs in with (e.g.
`vault write auth/userpass/users/<user> policies=git-vault-key` or the
equivalent for LDAP/OIDC/GitHub/AppRole). The key's URL for
`--key-resource-id` is built from your Vault address, the engine path, and
the key name:

    https://<vault-addr>:8200/v1/transit/keys/git-vault-key

## 2. Per-repo setup

    git vault install --provider vault \
      --key-resource-id https://<vault-addr>:8200/v1/transit/keys/git-vault-key

This validates the URL immediately with a real encrypt/decrypt round trip
— a typo'd URL or missing permission fails here, not at your first commit.

Add `--auto-login` to skip the confirmation prompt described below for
every developer on this repo. It's persisted to `.git-vault.yaml` as
`auto_login: true`, so it's a one-time, team-wide, repo-committed decision.

## 3. Per-developer setup

    git vault login

`git vault login` checks whether a valid token (`VAULT_TOKEN` or
`~/.vault-token`) already authorizes the configured key. If not, and
`vault` is on your PATH, it offers to run `vault login` for you (with
confirmation — it writes a token to disk, so it never runs without an
explicit yes). This only runs the default token auth method — if your org
uses OIDC, LDAP, GitHub, or AppRole, run your own
`vault login -method=<method>` first, then re-run `git vault login`.

### Auto-login

If `.git-vault.yaml` has `auto_login: true` (see `--auto-login` above),
`git vault login` and `git vault install` skip the confirmation prompt and
run `vault login` immediately when no valid token is found. `vault` still
has to be on PATH; this only removes the extra keystroke, not the login
flow itself.

## 4. Rotation

Vault Transit key rotation (`vault write -f transit/keys/git-vault-key/rotate`)
only keeps old key versions passively decryptable, governed by the key's
`min_decryption_version` — it never retires one automatically. Run
`git vault rotate` periodically (or after a suspected key exposure) to
force every tracked file's wrapped data key onto the key's current
version:

    vault write -f transit/keys/git-vault-key/rotate
    git vault rotate
    git add -A && git commit -m "Rotate git-vault key"

Unlike `azurekms`, `--key-resource-id` never encodes a version, so
`git vault rotate` doesn't rewrite `.git-vault.yaml` for this provider —
only the ciphertext changes.

Once every commit that matters has gone through a rotation, retire the old
version:

    vault write transit/keys/git-vault-key/config min_decryption_version=<new-version>

## Switching keys

To move to a different Transit key entirely (e.g. a different Vault
cluster or engine mount), use `git vault migrate`, not `rotate` —
`rotate` only re-seals under the *same* key's current version.

    git vault migrate --provider vault \
      --key-resource-id https://other-vault-addr:8200/v1/transit/keys/git-vault-key

## Troubleshooting

- `403` / permission denied — either no valid token was found, or the
  token's ACL policy doesn't grant `update` on
  `transit/encrypt/<key>`/`transit/decrypt/<key>`. Run `git vault login`,
  or ask whoever ran the admin bootstrap step to grant your policy.
- A malformed `--key-resource-id` fails with sops's own Vault URL parsing
  error, which names the expected shape
  (`https://vault.example.com:8200/v1/transit/keys/keyName`).
- "hcvault: no valid Vault token — run `vault login` first" — exactly
  that: no `VAULT_TOKEN` env var and no `~/.vault-token` file resolved a
  token Vault accepted for this key.
```

- [ ] **Step 2: Update `README.md`**

Change line 20 from:

```markdown
GCP KMS, AWS KMS, and Azure Key Vault are all available as team
key-sharing providers, authorized through your org's existing Google
Workspace, AWS IAM Identity Center, or Microsoft Entra ID SSO — see
[docs/gcpkms-provider.md](docs/gcpkms-provider.md),
[docs/awskms-provider.md](docs/awskms-provider.md), and
[docs/azurekms-provider.md](docs/azurekms-provider.md).
```

to:

```markdown
GCP KMS, AWS KMS, Azure Key Vault, and HashiCorp Vault are all available
as team key-sharing providers, authorized through your org's existing
Google Workspace, AWS IAM Identity Center, Microsoft Entra ID SSO, or
Vault token — see [docs/gcpkms-provider.md](docs/gcpkms-provider.md),
[docs/awskms-provider.md](docs/awskms-provider.md),
[docs/azurekms-provider.md](docs/azurekms-provider.md), and
[docs/vault-provider.md](docs/vault-provider.md).
```

Change the "Team key-sharing with cloud KMS" section (lines 74–82) from:

```markdown
For a shared key backed by your org's existing SSO (rather than a local
per-machine key or an out-of-band passphrase), see
[docs/gcpkms-provider.md](docs/gcpkms-provider.md) (Google Workspace
SSO), [docs/awskms-provider.md](docs/awskms-provider.md) (AWS IAM
Identity Center / SSO), or
[docs/azurekms-provider.md](docs/azurekms-provider.md) (Microsoft Entra
ID / `az login`).
```

to:

```markdown
For a shared key backed by your org's existing SSO (rather than a local
per-machine key or an out-of-band passphrase), see
[docs/gcpkms-provider.md](docs/gcpkms-provider.md) (Google Workspace
SSO), [docs/awskms-provider.md](docs/awskms-provider.md) (AWS IAM
Identity Center / SSO), [docs/azurekms-provider.md](docs/azurekms-provider.md)
(Microsoft Entra ID / `az login`), or
[docs/vault-provider.md](docs/vault-provider.md) (a self-hosted or HCP
Vault cluster / `vault login`).
```

- [ ] **Step 3: Promote `hashicorp/vault/api` to a direct dependency**

Run: `go mod tidy`
Expected: `go.mod`'s `require` block gains a direct
`github.com/hashicorp/vault/api v1.23.0` line (moved out of the
`// indirect` block), alongside `azure-sdk-for-go`/`aws-sdk-go-v2`. `go.sum`
may also change if `go mod tidy` picks up new transitive checksums.

- [ ] **Step 4: Run the full test suite and lint**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: all packages build, vet clean, all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add docs/vault-provider.md README.md go.mod go.sum
git commit -m "docs: add HashiCorp Vault provider guide, promote vault/api to direct dep"
```

---

## Plan Self-Review Notes

- **Spec coverage:** every spec section maps to a task — Key identifier/no-hand-rolled-parsing (Task 2), Non-goals/allowlist pinning (Task 2), architecture's login flow (Tasks 4–5), rotation (Task 6), migrate (Task 7), components-touched's docs/README (Task 8), testing (Tasks 1–2 for the provider, Tasks 3–7 for CLI wiring).
- **Task 4/5 split:** `install.go`'s round-trip case depends on `verifyVaultRoundTrip`/`attemptVaultLogin`, which conceptually belong to `login.go` (Task 5). Task 4 adds both functions to `login.go` without wiring `login`'s own command switch, so Task 4 is independently testable (its `install` tests pass without touching `login`'s behavior), and Task 5 only adds the `case` + its own tests on top — no task depends on a *later* task's code.
- **No `.git-vault.yaml` schema change:** `vault` reuses `Provider`, `KeyResourceID`, and `AutoLogin` exactly as gcpkms/awskms/azurekms do — no new config field.
