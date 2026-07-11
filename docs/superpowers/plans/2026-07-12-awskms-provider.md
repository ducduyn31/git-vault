# AWS KMS Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `awskms` as a second cloud KMS key provider for git-vault, mirroring the existing `gcpkms` provider exactly where AWS's SDK allows, and diverging only where AWS's actual behavior (credential-error shape, key rotation semantics) genuinely differs.

**Architecture:** A new `internal/keyservice/awskms` package wraps sops's `github.com/getsops/sops/v3/kms.MasterKey` (already a transitive dependency), following the identical `Provider{Name/Encrypt/Decrypt}` shape as `internal/keyservice/gcpkms`. It's wired through the same `vaultForProvider`/`install`/`login`/`rotate`/`migrate` switches gcpkms already uses, reusing the existing `KeyResourceID` and `AutoLogin` config fields and adding one new one, `AwsProfile`. A fake HTTP server (`awskmstest`, mirroring `gcpkmstest`) stands in for real AWS KMS in tests, since sops's AWS `MasterKey` has no public endpoint-override hook — the fake works by giving `MasterKey` a redirecting `http.Client`.

**Tech Stack:** Go 1.26, `github.com/getsops/sops/v3/kms`, `github.com/aws/aws-sdk-go-v2/{aws,credentials/ssocreds}` (already transitive deps per go.mod), `github.com/stretchr/testify/require`, cobra.

## Global Constraints

- Reuse `config.Config.KeyResourceID` for the AWS ARN — no new `--key-arn`/`key_arn` field (decided during brainstorming).
- Add `--aws-profile` / `config.Config.AwsProfile`, threaded through install/login/rotate/migrate the same way `KeyResourceID` already is.
- Only `ssocreds.InvalidTokenError` (expired/invalid cached SSO session) gets the interactive "run the fix for me" treatment (`errors.As`, exact type match — confirmed reachable through the AWS SDK's wrapped error chain by direct experiment). Every other AWS credential failure (never configured, IAM denied, malformed ARN) is surfaced as-is with a static hint — no substring-matching guesswork, per the design spec's Non-goals.
- `git vault rotate`'s follow-up message for awskms must not overclaim: AWS KMS's automatic key rotation is fully transparent (no version to disable/destroy), unlike GCP's.
- No new external Go module dependencies — `aws-sdk-go-v2/service/kms`, `aws-sdk-go-v2/credentials` (and its `ssocreds` subpackage) are already listed as indirect requires in go.mod; they just need to become direct (via `go mod tidy` in the final task).
- Full spec: `docs/superpowers/specs/2026-07-12-awskms-provider-design.md`.

---

### Task 1: `AwsProfile` config field

**Files:**
- Modify: `internal/config/config.go`
- Test: `internal/config/config_test.go`

**Interfaces:**
- Produces: `config.Config.AwsProfile string` (yaml tag `aws_profile,omitempty`) — consumed by every later task that builds a `config.Config` for awskms.

- [ ] **Step 1: Update the round-trip test to include the new field**

In `internal/config/config_test.go`, change `TestSaveLoad_RoundTrip`'s `want` literal:

```go
func TestSaveLoad_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".git-vault.yaml")
	want := Config{
		Provider:      "gcpkms",
		IssuerURL:     "https://issuer.example.com",
		ClientID:      "git-vault-cli",
		KeyResourceID: "projects/p/locations/global/keyRings/r/cryptoKeys/k",
		AwsProfile:    "team-sso",
		AutoLogin:     true,
	}

	require.NoError(t, Save(path, want))

	got, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, want, got)
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/config/... -run TestSaveLoad_RoundTrip -v`
Expected: FAIL — `unknown field AwsProfile in struct literal of type Config`

- [ ] **Step 3: Add the field**

In `internal/config/config.go`, add to `Config` (after `KeyResourceID`, before `AutoLogin`):

```go
	// AwsProfile names a local AWS CLI profile (~/.aws/config) to use
	// for credentials when Provider is awskms. Empty means the AWS
	// SDK's default credential chain (env vars, default profile,
	// instance role, etc). Ignored by every other provider.
	AwsProfile string `yaml:"aws_profile,omitempty"`
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/config/... -v`
Expected: PASS (all tests in the package)

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): add AwsProfile field for the awskms provider"
```

---

### Task 2: `awskmstest` fake AWS KMS server

**Files:**
- Create: `internal/keyservice/awskms/awskmstest/awskmstest.go`
- Test: `internal/keyservice/awskms/awskmstest/awskmstest_test.go`

**Interfaces:**
- Produces: `awskmstest.NewFakeServer() (httpClient *http.Client, credentials aws.CredentialsProvider, cleanup func(), err error)` — consumed by Task 3 (`awskms` package tests) and every CLI test task (4–8) that needs a fake AWS KMS backend.

- [ ] **Step 1: Write the failing test**

Create `internal/keyservice/awskms/awskmstest/awskmstest_test.go`:

```go
package awskmstest

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFakeServer_EncryptDecrypt_RoundTrip(t *testing.T) {
	hc, _, cleanup, err := NewFakeServer()
	require.NoError(t, err)
	defer cleanup()

	encBody, err := json.Marshal(map[string]any{
		"KeyId":     "arn:aws:kms:us-east-1:111111111111:key/test",
		"Plaintext": []byte("sops data key"),
	})
	require.NoError(t, err)

	var encOut struct{ CiphertextBlob []byte }
	doFakeRequest(t, hc, "TrentService.Encrypt", encBody, &encOut)
	require.NotEqual(t, "sops data key", string(encOut.CiphertextBlob))

	decBody, err := json.Marshal(map[string]any{"CiphertextBlob": encOut.CiphertextBlob})
	require.NoError(t, err)

	var decOut struct{ Plaintext []byte }
	doFakeRequest(t, hc, "TrentService.Decrypt", decBody, &decOut)
	require.Equal(t, "sops data key", string(decOut.Plaintext))
}

func TestFakeServer_Decrypt_TamperedCiphertextFails(t *testing.T) {
	hc, _, cleanup, err := NewFakeServer()
	require.NoError(t, err)
	defer cleanup()

	decBody, err := json.Marshal(map[string]any{"CiphertextBlob": []byte("not a real wrapped key")})
	require.NoError(t, err)

	resp := postFakeRequest(t, hc, "TrentService.Decrypt", decBody)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func postFakeRequest(t *testing.T, hc *http.Client, target string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "https://kms.us-east-1.amazonaws.com/", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("X-Amz-Target", target)
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	resp, err := hc.Do(req)
	require.NoError(t, err)
	return resp
}

func doFakeRequest(t *testing.T, hc *http.Client, target string, body []byte, out any) {
	t.Helper()
	resp := postFakeRequest(t, hc, target, body)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, out))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/keyservice/awskms/awskmstest/... -v`
Expected: FAIL to compile — `undefined: NewFakeServer`

- [ ] **Step 3: Write the fake server**

Create `internal/keyservice/awskms/awskmstest/awskmstest.go`:

```go
// Package awskmstest provides a fake AWS KMS server for testing code
// that uses internal/keyservice/awskms's Provider, without a real AWS
// account. It mirrors gcpkmstest's pattern, but at the HTTP layer: sops's
// kms.MasterKey has no public endpoint-override hook (unlike GCP's
// option.ClientOption — MasterKey's baseEndpoint field is unexported,
// for sops's own tests only), so this works by giving MasterKey an
// *http.Client whose Transport redirects every request to a local
// httptest.Server, regardless of the region-derived AWS host the SDK
// resolves.
package awskmstest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// marker prefixes every "ciphertext" this fake server produces, and is
// stripped back off on Decrypt — enough to prove real data flows through
// sops's kms.MasterKey end-to-end without performing real cryptography
// or touching a real AWS account.
const marker = "fake-kms-wrapped:"

type encryptRequest struct {
	KeyId     string
	Plaintext []byte
}

type decryptRequest struct {
	CiphertextBlob []byte
}

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	switch r.Header.Get("X-Amz-Target") {
	case "TrentService.Encrypt":
		var req encryptRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"CiphertextBlob": append([]byte(marker), req.Plaintext...),
			"KeyId":          req.KeyId,
		})
	case "TrentService.Decrypt":
		var req decryptRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !bytes.HasPrefix(req.CiphertextBlob, []byte(marker)) {
			http.Error(w, fmt.Sprintf("awskmstest: ciphertext missing fake marker, got %q", req.CiphertextBlob), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Plaintext": req.CiphertextBlob[len(marker):],
		})
	default:
		http.Error(w, fmt.Sprintf("awskmstest: unsupported X-Amz-Target %q", r.Header.Get("X-Amz-Target")), http.StatusBadRequest)
	}
}

// redirectTransport rewrites every outbound request's scheme/host to
// point at the fake server, regardless of what host the AWS SDK resolved
// the request to (kms.<region>.amazonaws.com).
type redirectTransport struct {
	scheme, host string
}

func (t redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme = t.scheme
	req.URL.Host = t.host
	req.Host = t.host
	return http.DefaultTransport.RoundTrip(req)
}

// NewFakeServer starts a fake AWS KMS HTTP server on a random local port
// and returns an *http.Client that redirects every request to it, plus
// static credentials so no real AWS credential chain lookup happens. The
// caller must invoke cleanup (e.g. via defer) to stop the server.
func NewFakeServer() (httpClient *http.Client, credentials aws.CredentialsProvider, cleanup func(), err error) {
	srv := httptest.NewServer(http.HandlerFunc(handler))
	u, err := url.Parse(srv.URL)
	if err != nil {
		srv.Close()
		return nil, nil, nil, fmt.Errorf("awskmstest: parse server URL: %w", err)
	}

	httpClient = &http.Client{Transport: redirectTransport{scheme: u.Scheme, host: u.Host}}
	credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "fake", SecretAccessKey: "fake"}, nil
	})
	return httpClient, credentials, srv.Close, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/keyservice/awskms/awskmstest/... -v`
Expected: PASS (both tests)

- [ ] **Step 5: Commit**

```bash
git add internal/keyservice/awskms/awskmstest/
git commit -m "feat(awskms): add fake AWS KMS HTTP server for testing"
```

---

### Task 3: `awskms.Provider`

**Files:**
- Create: `internal/keyservice/awskms/awskms.go`
- Test: `internal/keyservice/awskms/awskms_test.go`

**Interfaces:**
- Consumes: `awskmstest.NewFakeServer()` (Task 2).
- Produces: `awskms.Name = "awskms"`, `awskms.New(awsProfile string) Provider`, `Provider.Name()/Encrypt(ctx, keyID, plaintext)/Decrypt(ctx, keyID, ciphertext)`, `awskms.SetTestOverridesForTesting(hc *http.Client, creds aws.CredentialsProvider) (restore func())`, `awskms.ErrExpiredSSOSession` — all consumed by Tasks 4–8.

- [ ] **Step 1: Write the failing test**

Create `internal/keyservice/awskms/awskms_test.go`:

```go
package awskms

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/credentials/ssocreds"
	"github.com/stretchr/testify/require"

	"github.com/ducduyn31/git-vault/internal/keyservice/awskms/awskmstest"
)

const testARN = "arn:aws:kms:us-east-1:111111111111:key/test"

func TestProvider_EncryptDecrypt_RoundTrip(t *testing.T) {
	hc, creds, cleanup, err := awskmstest.NewFakeServer()
	require.NoError(t, err)
	defer cleanup()
	restore := SetTestOverridesForTesting(hc, creds)
	defer restore()

	p := New("")
	require.Equal(t, Name, p.Name())

	ciphertext, err := p.Encrypt(context.Background(), testARN, []byte("sops data key"))
	require.NoError(t, err)
	require.NotEqual(t, "sops data key", string(ciphertext))

	plaintext, err := p.Decrypt(context.Background(), testARN, ciphertext)
	require.NoError(t, err)
	require.Equal(t, "sops data key", string(plaintext))
}

func TestProvider_Decrypt_TamperedCiphertextFails(t *testing.T) {
	hc, creds, cleanup, err := awskmstest.NewFakeServer()
	require.NoError(t, err)
	defer cleanup()
	restore := SetTestOverridesForTesting(hc, creds)
	defer restore()

	p := New("")
	_, err = p.Decrypt(context.Background(), testARN, []byte("not a real wrapped key"))
	require.Error(t, err)
}

func TestProvider_Encrypt_InvalidARNFails(t *testing.T) {
	p := New("")
	_, err := p.Encrypt(context.Background(), "not-an-arn", []byte("data"))
	require.ErrorContains(t, err, "no valid ARN found")
}

func TestFriendlyLoginErr_RewritesExpiredSSOSession(t *testing.T) {
	err := friendlyLoginErr("encrypt", fmt.Errorf("wrapped: %w", &ssocreds.InvalidTokenError{}))
	require.ErrorIs(t, err, ErrExpiredSSOSession)
}

func TestFriendlyLoginErr_PassesThroughOtherErrors(t *testing.T) {
	err := friendlyLoginErr("encrypt", errors.New("permission denied"))
	require.ErrorContains(t, err, "awskms: encrypt: permission denied")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/keyservice/awskms/... -v`
Expected: FAIL to compile — `undefined: New`, `undefined: SetTestOverridesForTesting`, `undefined: ErrExpiredSSOSession`, `undefined: friendlyLoginErr`

- [ ] **Step 3: Write the Provider**

Create `internal/keyservice/awskms/awskms.go`:

```go
// Package awskms implements a keyservice.Provider backed by AWS KMS,
// authorized via whatever credentials the AWS SDK's default credential
// chain resolves on this machine (env vars, shared config/credentials
// file, or — for team key-sharing via SSO — a named profile set up with
// `aws configure sso`). Unlike internal/keyservice/local and
// internal/keyservice/passphrase, git-vault holds no key material of its
// own here: AWS IAM on the KMS key is the only access control, and
// git-vault never runs its own SSO device flow — `git vault login`
// (internal/cli/login.go) only ever shells out to the real `aws sso
// login`, and only with the user's explicit confirmation (or
// config.Config.AutoLogin). See
// docs/superpowers/specs/2026-07-12-awskms-provider-design.md.
package awskms

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/ssocreds"
	sopskms "github.com/getsops/sops/v3/kms"
)

// Name is the provider name used in "awskms:<arn>" key identifiers (see
// internal/keyservice.Server).
const Name = "awskms"

// testHTTPClient and testCredentials override every MasterKey this
// package's Providers create. Set only via SetTestOverridesForTesting.
var (
	testHTTPClient  *http.Client
	testCredentials aws.CredentialsProvider
)

// SetTestOverridesForTesting points every Provider subsequently created
// by New at a fake AWS KMS HTTP server instead of real AWS
// infrastructure (see the awskmstest package), and supplies static
// credentials so no real credential chain lookup happens. It returns a
// function that restores the previous overrides — call it via defer. For
// use in tests only.
func SetTestOverridesForTesting(hc *http.Client, creds aws.CredentialsProvider) (restore func()) {
	prevHC, prevCreds := testHTTPClient, testCredentials
	testHTTPClient, testCredentials = hc, creds
	return func() { testHTTPClient, testCredentials = prevHC, prevCreds }
}

// Provider is backed by an AWS KMS key, identified per-call by keyID (a
// KMS ARN) rather than fixed at construction — the ARN lives in
// git-vault's repo-tracked config (internal/config.Config.KeyResourceID),
// not in this Provider. awsProfile names a local AWS CLI profile to
// resolve credentials from; empty means the SDK's default credential
// chain.
type Provider struct {
	awsProfile  string
	httpClient  *http.Client
	credentials aws.CredentialsProvider
}

// New returns a Provider using real AWS KMS, unless
// SetTestOverridesForTesting has redirected it to a fake server.
func New(awsProfile string) Provider {
	return Provider{awsProfile: awsProfile, httpClient: testHTTPClient, credentials: testCredentials}
}

func (p Provider) Name() string { return Name }

// Encrypt wraps plaintext (a sops data key) with the AWS KMS key named by
// keyID (an ARN of the form arn:aws:kms:<region>:<account>:key/<id>).
func (p Provider) Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error) {
	key := sopskms.NewMasterKeyFromArn(keyID, nil, p.awsProfile)
	p.apply(key)
	if err := key.EncryptContext(ctx, plaintext); err != nil {
		return nil, friendlyLoginErr("encrypt", err)
	}
	return key.EncryptedDataKey(), nil
}

// Decrypt unwraps ciphertext (see Encrypt) with the AWS KMS key named by
// keyID.
func (p Provider) Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error) {
	key := sopskms.NewMasterKeyFromArn(keyID, nil, p.awsProfile)
	p.apply(key)
	key.SetEncryptedDataKey(ciphertext)
	plaintext, err := key.DecryptContext(ctx)
	if err != nil {
		return nil, friendlyLoginErr("decrypt", err)
	}
	return plaintext, nil
}

// apply configures key with this Provider's test overrides, if any.
func (p Provider) apply(key *sopskms.MasterKey) {
	if p.httpClient != nil {
		sopskms.NewHTTPClient(p.httpClient).ApplyToMasterKey(key)
	}
	if p.credentials != nil {
		sopskms.NewCredentialsProvider(p.credentials).ApplyToMasterKey(key)
	}
}

// ErrExpiredSSOSession is returned (via friendlyLoginErr) when the AWS
// SDK's cached SSO token has expired or is otherwise invalid
// (ssocreds.InvalidTokenError). It's a sentinel rather than just a
// message so callers — namely internal/cli/login.go — can detect this
// specific, fixable case with errors.Is and offer to run `aws sso login`
// themselves, instead of every caller re-parsing error text. Every other
// AWS credential failure (never configured, IAM denied) is passed
// through as-is — see
// docs/superpowers/specs/2026-07-12-awskms-provider-design.md's
// Non-goals for why only this one case gets special handling.
var ErrExpiredSSOSession = errors.New("awskms: AWS SSO session has expired or is invalid — run `aws sso login` first")

// friendlyLoginErr rewrites an expired/invalid cached SSO token error
// into ErrExpiredSSOSession. ssocreds.InvalidTokenError is an exported
// type (unlike the ADC-missing case gcpkms handles by substring match),
// so errors.As reliably detects it through the AWS SDK's wrapped error
// chain. Any other error (e.g. IAM permission denied, malformed ARN, no
// credentials configured at all) is wrapped with op but otherwise passed
// through as-is.
func friendlyLoginErr(op string, err error) error {
	var invalidToken *ssocreds.InvalidTokenError
	if errors.As(err, &invalidToken) {
		return ErrExpiredSSOSession
	}
	return fmt.Errorf("awskms: %s: %w", op, err)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/keyservice/awskms/... -v`
Expected: PASS (all tests in both `awskms` and `awskmstest`)

- [ ] **Step 5: Commit**

```bash
git add internal/keyservice/awskms/awskms.go internal/keyservice/awskms/awskms_test.go
git commit -m "feat(awskms): add Provider wrapping sops's AWS KMS MasterKey"
```

---

### Task 4: Wire `awskms` into `vaultForProvider`

**Files:**
- Modify: `internal/cli/vault.go`
- Test: `internal/cli/vault_test.go`

**Interfaces:**
- Consumes: `awskms.New`, `awskms.Name`, `awskms.SetTestOverridesForTesting`, `awskmstest.NewFakeServer` (Tasks 2–3); `config.Config.AwsProfile` (Task 1).
- Produces: `newAWSKMSVault(cfg config.Config) (*vault.Vault, []string, error)`; `vaultForProvider` now handles `case awskms.Name` — consumed by Tasks 5–8.

- [ ] **Step 1: Write the failing test**

Add to `internal/cli/vault_test.go`:

```go
func TestVaultForProvider_AWSKMS(t *testing.T) {
	hc, creds, cleanup, err := awskmstest.NewFakeServer()
	require.NoError(t, err)
	defer cleanup()
	restore := awskms.SetTestOverridesForTesting(hc, creds)
	defer restore()

	v, recipients, err := vaultForProvider(config.Config{
		Provider:      awskms.Name,
		KeyResourceID: "arn:aws:kms:us-east-1:111111111111:key/test",
	})
	require.NoError(t, err)
	require.NotNil(t, v)
	require.Equal(t, []string{"awskms:arn:aws:kms:us-east-1:111111111111:key/test"}, recipients)
}
```

Add these imports to `internal/cli/vault_test.go`'s import block:

```go
	"github.com/ducduyn31/git-vault/internal/keyservice/awskms"
	"github.com/ducduyn31/git-vault/internal/keyservice/awskms/awskmstest"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cli/... -run TestVaultForProvider_AWSKMS -v`
Expected: FAIL to compile — `undefined: newAWSKMSVault` is not yet referenced, but `vaultForProvider` will return `unknown provider "awskms"` — actually it will compile fine and FAIL at runtime with `unknown provider "awskms"` since the import itself resolves. Expected failure: `Error: unknown provider "awskms" in .git-vault.yaml`.

- [ ] **Step 3: Wire it in**

In `internal/cli/vault.go`, add the import `"github.com/ducduyn31/git-vault/internal/keyservice/awskms"`, then add this function after `newGCPKMSVault`:

```go
// newAWSKMSVault builds a Vault dispatching to AWS KMS, along with the
// "<provider>:<key-id>" recipient string for cfg.KeyResourceID (an AWS
// KMS ARN). Unlike local/passphrase, the key material lives entirely in
// AWS — this Provider holds no identity of its own beyond whatever the
// default AWS credential chain (or cfg.AwsProfile) resolves to.
func newAWSKMSVault(cfg config.Config) (*vault.Vault, []string, error) {
	registry := keyservice.NewRegistry()
	if err := registry.Register(awskms.New(cfg.AwsProfile)); err != nil {
		return nil, nil, err
	}
	server := keyservice.NewServer(registry)

	return vault.New(server), []string{awskms.Name + ":" + cfg.KeyResourceID}, nil
}
```

Then add a case to `vaultForProvider`'s switch, right after `case gcpkms.Name`:

```go
	case awskms.Name:
		return newAWSKMSVault(cfg)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/cli/... -v`
Expected: PASS (all tests in the package)

- [ ] **Step 5: Commit**

```bash
git add internal/cli/vault.go internal/cli/vault_test.go
git commit -m "feat(cli): wire awskms into vaultForProvider"
```

---

### Task 5: `install --provider awskms`

**Files:**
- Modify: `internal/cli/install.go`
- Test: `internal/cli/install_test.go`

**Interfaces:**
- Consumes: `newAWSKMSVault`/`vaultForProvider` awskms case (Task 4); `verifyAWSKMSRoundTrip`/`attemptAWSSSOLogin` (Task 6 — see note below).
- Produces: `--aws-profile` flag; `install` accepts `--provider=awskms`, requiring `--key-resource-id`.

> **Note on ordering:** This task's `RunE` calls `verifyAWSKMSRoundTrip` and `attemptAWSSSOLogin`, which Task 6 defines in `login.go`. Since Go compiles a package as a whole, implement Tasks 5 and 6 together if working sequentially in one session (there's no way to compile Task 5 alone without Task 6's functions existing). If using subagent-driven execution, give one worker both tasks' steps back-to-back before running tests.

- [ ] **Step 1: Write the failing tests**

Add to `internal/cli/install_test.go`:

```go
func TestInstallCmd_AWSKMS_WritesConfigAndValidates(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	hc, creds, cleanup, err := awskmstest.NewFakeServer()
	require.NoError(t, err)
	defer cleanup()
	restore := awskms.SetTestOverridesForTesting(hc, creds)
	defer restore()

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{
		"install", "--provider=" + awskms.Name,
		"--key-resource-id=arn:aws:kms:us-east-1:111111111111:key/test",
		"--aws-profile=team-sso",
	})
	require.NoError(t, cmd.Execute())

	require.Contains(t, out.String(), "Recipient: awskms:arn:aws:kms:us-east-1:111111111111:key/test")

	cfg, err := config.Load(config.DefaultFileName)
	require.NoError(t, err)
	require.Equal(t, awskms.Name, cfg.Provider)
	require.Equal(t, "arn:aws:kms:us-east-1:111111111111:key/test", cfg.KeyResourceID)
	require.Equal(t, "team-sso", cfg.AwsProfile)
}

func TestInstallCmd_AWSKMS_MissingKeyResourceIDFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"install", "--provider=" + awskms.Name})

	err := cmd.Execute()
	require.ErrorContains(t, err, "--key-resource-id is required")
}

func TestInstallCmd_AWSKMS_FailsWithoutReachableKMS(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"install", "--provider=" + awskms.Name,
		"--key-resource-id=not-an-arn",
	})

	err := cmd.Execute()
	require.Error(t, err)

	_, gitErr := exec.Command("git", "config", "--get", "filter.git-vault.clean").Output()
	require.Error(t, gitErr, "git config must not be set when install fails the KMS round trip")
}
```

Add these imports to `internal/cli/install_test.go`'s import block:

```go
	"github.com/ducduyn31/git-vault/internal/keyservice/awskms"
	"github.com/ducduyn31/git-vault/internal/keyservice/awskms/awskmstest"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cli/... -run TestInstallCmd_AWSKMS -v`
Expected: FAIL — `--provider=awskms` isn't validated yet, so `TestInstallCmd_AWSKMS_MissingKeyResourceIDFails` fails (no error raised); the other two fail because `verifyAWSKMSRoundTrip`/`attemptAWSSSOLogin` don't exist (compile error) until Task 6's code is also in place.

- [ ] **Step 3: Update install.go**

Replace `internal/cli/install.go` in full with:

```go
package cli

import (
	"errors"
	"fmt"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/keyservice/awskms"
	"github.com/ducduyn31/git-vault/internal/keyservice/gcpkms"
	"github.com/ducduyn31/git-vault/internal/keyservice/local"
	"github.com/ducduyn31/git-vault/internal/ui"
)

func newInstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Register the git-vault filter driver",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			global, err := cmd.Flags().GetBool("global")
			if err != nil {
				return err
			}
			providerName, err := cmd.Flags().GetString("provider")
			if err != nil {
				return err
			}
			keyResourceID, err := cmd.Flags().GetString("key-resource-id")
			if err != nil {
				return err
			}
			awsProfile, err := cmd.Flags().GetString("aws-profile")
			if err != nil {
				return err
			}
			autoLogin, err := cmd.Flags().GetBool("auto-login")
			if err != nil {
				return err
			}

			if (providerName == gcpkms.Name || providerName == awskms.Name) && keyResourceID == "" {
				return fmt.Errorf("git vault install: --key-resource-id is required for provider %q", providerName)
			}

			cfg := config.Config{Provider: providerName, KeyResourceID: keyResourceID, AwsProfile: awsProfile, AutoLogin: autoLogin}

			// vaultForProvider both validates providerName (its default
			// case errors on anything unknown) and resolves the
			// "<provider>:<key-id>" recipient to print, via the same
			// switch newVault() uses at encrypt/decrypt/clean/smudge time
			// — no separate recipient-resolution switch needed here.
			_, recipients, err := vaultForProvider(cfg)
			if err != nil {
				return fmt.Errorf("git vault install: %w", err)
			}
			recipient := recipients[0]

			switch providerName {
			case gcpkms.Name:
				err := verifyGCPKMSRoundTrip(cmd.Context(), keyResourceID)
				if errors.Is(err, gcpkms.ErrNoCredentials) && attemptGcloudLogin(cmd, autoLogin) {
					err = verifyGCPKMSRoundTrip(cmd.Context(), keyResourceID)
				}
				if err != nil {
					return fmt.Errorf("git vault install: %w", err)
				}
			case awskms.Name:
				err := verifyAWSKMSRoundTrip(cmd.Context(), keyResourceID, awsProfile)
				if errors.Is(err, awskms.ErrExpiredSSOSession) && attemptAWSSSOLogin(cmd, awsProfile, autoLogin) {
					err = verifyAWSKMSRoundTrip(cmd.Context(), keyResourceID, awsProfile)
				}
				if err != nil {
					return fmt.Errorf("git vault install: %w", err)
				}
			}

			settings := []struct{ key, value string }{
				{"filter.git-vault.clean", "git-vault clean %f"},
				{"filter.git-vault.smudge", "git-vault smudge %f"},
				{"filter.git-vault.required", "true"},
			}
			for _, s := range settings {
				if err := setGitConfig(global, s.key, s.value); err != nil {
					return fmt.Errorf("git vault install: %w", err)
				}
			}

			if err := config.Save(config.DefaultFileName, cfg); err != nil {
				return fmt.Errorf("git vault install: write %s: %w", config.DefaultFileName, err)
			}

			scope := "repo"
			if global {
				scope = "global"
			}
			ui.New(cmd.OutOrStdout()).Info(fmt.Sprintf("Installed git-vault filter driver (%s scope).\nRecipient: %s", scope, recipient))
			return nil
		},
	}
	cmd.Flags().Bool("global", false, "install the filter driver in the user's global git config")
	cmd.Flags().String("provider", local.Name, "key provider to use (local, passphrase, gcpkms, awskms)")
	cmd.Flags().String("key-resource-id", "", "GCP KMS resource ID or AWS KMS ARN (required when --provider gcpkms or awskms)")
	cmd.Flags().String("aws-profile", "", "named AWS profile to use for credentials (awskms only)")
	cmd.Flags().Bool("auto-login", false, "skip the confirmation prompt and run the provider's login command automatically when credentials are missing (gcpkms, awskms)")
	return cmd
}

func setGitConfig(global bool, key, value string) error {
	args := []string{"config"}
	if global {
		args = append(args, "--global")
	}
	args = append(args, key, value)

	out, err := exec.Command("git", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("git %s: %w: %s", key, err, out)
	}
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

This requires Task 6's `login.go` changes to be in place first (see the ordering note above). Once both are done, run:

Run: `go test ./internal/cli/... -v`
Expected: PASS (all tests in the package)

- [ ] **Step 5: Commit**

```bash
git add internal/cli/install.go internal/cli/install_test.go
git commit -m "feat(cli): accept --provider awskms in install, with --aws-profile"
```

---

### Task 6: `login` support for `awskms`, restructured as a switch

**Files:**
- Modify: `internal/cli/login.go`
- Test: `internal/cli/login_test.go`

**Interfaces:**
- Consumes: `awskms.New`, `awskms.Name`, `awskms.ErrExpiredSSOSession` (Task 3).
- Produces: `verifyAWSKMSRoundTrip(ctx context.Context, keyResourceID, awsProfile string) error`, `attemptAWSSSOLogin(cmd *cobra.Command, awsProfile string, autoLogin bool) bool` — consumed by Task 5 (`install.go`) and Task 6 itself (`login.go`'s `RunE`). Also renames `gcpkmsLoginProbe` to `loginProbe` (shared by both providers) — no other file references the old name.

- [ ] **Step 1: Write the failing tests**

Add to `internal/cli/login_test.go`:

```go
func TestLoginCmd_AWSKMS_Succeeds(t *testing.T) {
	chdirTemp(t)
	require.NoError(t, config.Save(config.DefaultFileName, config.Config{
		Provider:      awskms.Name,
		KeyResourceID: "arn:aws:kms:us-east-1:111111111111:key/test",
	}))

	hc, creds, cleanup, err := awskmstest.NewFakeServer()
	require.NoError(t, err)
	defer cleanup()
	restore := awskms.SetTestOverridesForTesting(hc, creds)
	defer restore()

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{"login"})
	require.NoError(t, cmd.Execute())
	require.Contains(t, out.String(), "authorized")
}

func TestLoginCmd_AWSKMS_FailsWithoutReachableKMS(t *testing.T) {
	chdirTemp(t)
	require.NoError(t, config.Save(config.DefaultFileName, config.Config{
		Provider:      awskms.Name,
		KeyResourceID: "not-an-arn",
	}))

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"login"})
	require.Error(t, cmd.Execute())
}

func fakeAwsCLI(t *testing.T, exitCode int) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake aws script assumes a POSIX shell")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "aws")
	contents := fmt.Sprintf("#!/bin/sh\nexit %d\n", exitCode)
	require.NoError(t, os.WriteFile(script, []byte(contents), 0o755))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestAttemptAWSSSOLogin_NoAWSCLIOnPath(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	out := &bytes.Buffer{}
	require.False(t, attemptAWSSSOLogin(promptCmd(bytes.NewBufferString("y\n"), out), "", false))
	require.Empty(t, out.String())
}

func TestAttemptAWSSSOLogin_Declined(t *testing.T) {
	fakeAwsCLI(t, 0)
	out := &bytes.Buffer{}
	require.False(t, attemptAWSSSOLogin(promptCmd(bytes.NewBufferString("n\n"), out), "", false))
	require.Contains(t, out.String(), "Run `aws sso login` now?")
}

func TestAttemptAWSSSOLogin_ConfirmedAndCLISucceeds(t *testing.T) {
	fakeAwsCLI(t, 0)
	out := &bytes.Buffer{}
	require.True(t, attemptAWSSSOLogin(promptCmd(bytes.NewBufferString("y\n"), out), "", false))
}

func TestAttemptAWSSSOLogin_ConfirmedButCLIFails(t *testing.T) {
	fakeAwsCLI(t, 1)
	out := &bytes.Buffer{}
	require.False(t, attemptAWSSSOLogin(promptCmd(bytes.NewBufferString("yes\n"), out), "", false))
}

func TestAttemptAWSSSOLogin_AutoLoginSkipsPrompt(t *testing.T) {
	fakeAwsCLI(t, 0)
	out := &bytes.Buffer{}
	require.True(t, attemptAWSSSOLogin(promptCmd(bytes.NewBufferString(""), out), "", true))
	require.Empty(t, out.String())
}

func TestAttemptAWSSSOLogin_AutoLoginStillNeedsCLI(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	out := &bytes.Buffer{}
	require.False(t, attemptAWSSSOLogin(promptCmd(bytes.NewBufferString(""), out), "", true))
}

func TestAttemptAWSSSOLogin_IncludesProfileInPrompt(t *testing.T) {
	fakeAwsCLI(t, 0)
	out := &bytes.Buffer{}
	require.True(t, attemptAWSSSOLogin(promptCmd(bytes.NewBufferString("y\n"), out), "team-sso", false))
	require.Contains(t, out.String(), "aws sso login --profile team-sso")
}
```

Add these imports to `internal/cli/login_test.go`'s import block:

```go
	"github.com/ducduyn31/git-vault/internal/keyservice/awskms"
	"github.com/ducduyn31/git-vault/internal/keyservice/awskms/awskmstest"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cli/... -run 'TestLoginCmd_AWSKMS|TestAttemptAWSSSOLogin' -v`
Expected: FAIL to compile — `undefined: attemptAWSSSOLogin`

- [ ] **Step 3: Replace login.go**

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

	"github.com/ducduyn31/git-vault/internal/keyservice/awskms"
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
			case awskms.Name:
				err = verifyAWSKMSRoundTrip(cmd.Context(), cfg.KeyResourceID, cfg.AwsProfile)
				if errors.Is(err, awskms.ErrExpiredSSOSession) && attemptAWSSSOLogin(cmd, cfg.AwsProfile, cfg.AutoLogin) {
					err = verifyAWSKMSRoundTrip(cmd.Context(), cfg.KeyResourceID, cfg.AwsProfile)
				}
				if err != nil {
					return fmt.Errorf("git vault login: %w", err)
				}
				_, err = fmt.Fprintln(cmd.OutOrStdout(), "AWS KMS round trip succeeded — this machine is authorized.")
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

// attemptAWSSSOLogin tries to fix an expired/invalid cached SSO session
// (awskms.ErrExpiredSSOSession) by running `aws sso login`, scoped to
// awsProfile if set. It mirrors attemptGcloudLogin's confirm-before-exec
// shape exactly, including the autoLogin (config.Config.AutoLogin)
// opt-out. AWS's other credential failure modes (never configured,
// permission denied) are not handled here — see
// docs/superpowers/specs/2026-07-12-awskms-provider-design.md's
// Non-goals.
func attemptAWSSSOLogin(cmd *cobra.Command, awsProfile string, autoLogin bool) bool {
	path, err := exec.LookPath("aws")
	if err != nil {
		return false
	}

	args := []string{"sso", "login"}
	if awsProfile != "" {
		args = append(args, "--profile", awsProfile)
	}
	displayCmd := "aws " + strings.Join(args, " ")

	if !autoLogin {
		if _, err := fmt.Fprintf(cmd.OutOrStdout(), "AWS SSO session expired or missing. Run `%s` now? [y/N] ", displayCmd); err != nil {
			return false
		}
		line, _ := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
		if answer := strings.ToLower(strings.TrimSpace(line)); answer != "y" && answer != "yes" {
			return false
		}
	}

	awsCmd := exec.CommandContext(cmd.Context(), path, args...)
	awsCmd.Stdin = cmd.InOrStdin()
	awsCmd.Stdout = cmd.OutOrStdout()
	awsCmd.Stderr = cmd.ErrOrStderr()
	return awsCmd.Run() == nil
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

// verifyAWSKMSRoundTrip is verifyGCPKMSRoundTrip's AWS KMS equivalent —
// see its doc comment. awsProfile is passed through to awskms.New even
// when empty (meaning: use the default AWS credential chain).
func verifyAWSKMSRoundTrip(ctx context.Context, keyResourceID, awsProfile string) error {
	provider := awskms.New(awsProfile)
	ciphertext, err := provider.Encrypt(ctx, keyResourceID, []byte(loginProbe))
	if err != nil {
		return err
	}
	plaintext, err := provider.Decrypt(ctx, keyResourceID, ciphertext)
	if err != nil {
		return err
	}
	if string(plaintext) != loginProbe {
		return fmt.Errorf("awskms: round trip returned unexpected plaintext")
	}
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/cli/... -v`
Expected: PASS (all tests in the package, including Task 5's install tests, now that both files are in place)

- [ ] **Step 5: Commit**

```bash
git add internal/cli/login.go internal/cli/login_test.go internal/cli/install.go internal/cli/install_test.go
git commit -m "feat(cli): add awskms support to git vault login/install"
```

---

### Task 7: `rotate` support for `awskms`

**Files:**
- Modify: `internal/cli/rotate.go`
- Test: `internal/cli/rotate_test.go`

**Interfaces:**
- Consumes: `vaultForProvider` awskms case (Task 4).

- [ ] **Step 1: Write the failing test**

Add to `internal/cli/rotate_test.go`:

```go
func TestRotateCmd_AWSKMS_RoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	hc, creds, cleanup, err := awskmstest.NewFakeServer()
	require.NoError(t, err)
	defer cleanup()
	restore := awskms.SetTestOverridesForTesting(hc, creds)
	defer restore()

	original := setupTrackedEncryptedFileWithConfig(t, config.Config{
		Provider:      awskms.Name,
		KeyResourceID: "arn:aws:kms:us-east-1:111111111111:key/test",
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
	require.NotEqual(t, string(sealedBefore), string(sealedAfter), "rotate must force a fresh KMS Encrypt call")

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
	"github.com/ducduyn31/git-vault/internal/keyservice/awskms"
	"github.com/ducduyn31/git-vault/internal/keyservice/awskms/awskmstest"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cli/... -run TestRotateCmd_AWSKMS -v`
Expected: FAIL — `git vault rotate: rotation not supported for provider "awskms"`

- [ ] **Step 3: Add the awskms case**

In `internal/cli/rotate.go`, add the import `"github.com/ducduyn31/git-vault/internal/keyservice/awskms"`, then add a case to the first `switch cfg.Provider` block, right after `case gcpkms.Name` (before `default`):

```go
		case awskms.Name:
			// The ARN never changes across an AWS-side rotation, and
			// AWS KMS's automatic annual rotation is fully transparent
			// — there is no "current version" exposed to target the
			// way GCP's key versions are. Re-sealing every file still
			// forces a fresh KMS Encrypt call; it just doesn't let old
			// backing material be individually retired afterward the
			// way gcpkms's case does.
			newVault, newRecipients, err = vaultForProvider(cfg)
			if err != nil {
				return fmt.Errorf("git vault rotate: %w", err)
			}
			oldVault = newVault
```

Then add a case to the second `switch cfg.Provider` block (the `followUp` message switch), right after `case gcpkms.Name`:

```go
		case awskms.Name:
			followUp = "AWS KMS rotates its backing key material automatically and transparently — unlike GCP, there is no old version to disable or destroy afterward; this re-encryption is defense-in-depth only. To actually retire a compromised key, use `git vault migrate` to a different KMS key instead."
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/cli/... -v`
Expected: PASS (all tests in the package)

- [ ] **Step 5: Commit**

```bash
git add internal/cli/rotate.go internal/cli/rotate_test.go
git commit -m "feat(cli): support git vault rotate for awskms"
```

---

### Task 8: `migrate` support for `awskms`

**Files:**
- Modify: `internal/cli/migrate.go`
- Test: `internal/cli/migrate_test.go`

**Interfaces:**
- Consumes: `vaultForProvider` awskms case (Task 4).

- [ ] **Step 1: Write the failing tests**

Add to `internal/cli/migrate_test.go`:

```go
func TestMigrateCmd_AWSKMSToAWSKMS_DifferentKey_RoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	hc, creds, cleanup, err := awskmstest.NewFakeServer()
	require.NoError(t, err)
	defer cleanup()
	restore := awskms.SetTestOverridesForTesting(hc, creds)
	defer restore()

	original := setupTrackedEncryptedFileWithConfig(t, config.Config{
		Provider:      awskms.Name,
		KeyResourceID: "arn:aws:kms:us-east-1:111111111111:key/key-a",
	})

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{
		"migrate", "--provider=" + awskms.Name,
		"--key-resource-id=arn:aws:kms:us-east-1:111111111111:key/key-b",
	})
	require.NoError(t, cmd.Execute())
	require.Contains(t, out.String(), "Migrated 1 file")

	cfg, err := config.Load(config.DefaultFileName)
	require.NoError(t, err)
	require.Equal(t, awskms.Name, cfg.Provider)
	require.Equal(t, "arn:aws:kms:us-east-1:111111111111:key/key-b", cfg.KeyResourceID)

	decryptCmd := NewRootCmd()
	decryptCmd.SetOut(&bytes.Buffer{})
	decryptCmd.SetArgs([]string{"decrypt", "secret.yaml"})
	require.NoError(t, decryptCmd.Execute())

	opened, err := os.ReadFile("secret.yaml")
	require.NoError(t, err)
	require.Equal(t, original, string(opened))
}

func TestMigrateCmd_AWSKMSToAWSKMS_SameKeyFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	hc, creds, cleanup, err := awskmstest.NewFakeServer()
	require.NoError(t, err)
	defer cleanup()
	restore := awskms.SetTestOverridesForTesting(hc, creds)
	defer restore()

	setupTrackedEncryptedFileWithConfig(t, config.Config{
		Provider:      awskms.Name,
		KeyResourceID: "arn:aws:kms:us-east-1:111111111111:key/key-a",
	})

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"migrate", "--provider=" + awskms.Name,
		"--key-resource-id=arn:aws:kms:us-east-1:111111111111:key/key-a",
	})
	err = cmd.Execute()
	require.ErrorContains(t, err, "identical to the current key")
}

func TestMigrateCmd_AWSKMSTarget_MissingKeyResourceIDFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	setupTrackedEncryptedFile(t, local.Name)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"migrate", "--provider=" + awskms.Name})

	err := cmd.Execute()
	require.ErrorContains(t, err, "--key-resource-id is required")
}
```

Add these imports to `internal/cli/migrate_test.go`'s import block:

```go
	"github.com/ducduyn31/git-vault/internal/keyservice/awskms"
	"github.com/ducduyn31/git-vault/internal/keyservice/awskms/awskmstest"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cli/... -run TestMigrateCmd_AWSKMS -v`
Expected: FAIL — `TestMigrateCmd_AWSKMSTarget_MissingKeyResourceIDFails` fails because no `--key-resource-id` check exists for awskms yet; the other two fail with `unknown provider "awskms"` didn't trigger, but the recipient/config assertions fail since `--aws-profile`/awskms path isn't validated the same way.

- [ ] **Step 3: Update migrate.go**

Replace `internal/cli/migrate.go` in full with:

```go
package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/gitattr"
	"github.com/ducduyn31/git-vault/internal/keyservice/awskms"
	"github.com/ducduyn31/git-vault/internal/keyservice/gcpkms"
	"github.com/ducduyn31/git-vault/internal/ui"
)

// newMigrateCmd re-seals every tracked file from the repo's current
// provider/key to a different target, then updates .git-vault.yaml. A
// target that resolves to the exact same key as the current one is
// rejected rather than silently no-op'd: for local/passphrase that's
// always true (each has exactly one key source); for gcpkms/awskms it's
// only true when the resource ID also matches, since two different
// targets can share the provider name but name different keys. See
// docs/superpowers/specs/2026-07-11-migrate-provider-design.md,
// docs/superpowers/specs/2026-07-11-gcpkms-provider-design.md, and
// docs/superpowers/specs/2026-07-12-awskms-provider-design.md.
func newMigrateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Re-seal all tracked files under a different key provider",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := cmd.Flags().GetString("provider")
			if err != nil {
				return err
			}
			if target == "" {
				return fmt.Errorf("git vault migrate: --provider is required")
			}
			keyResourceID, err := cmd.Flags().GetString("key-resource-id")
			if err != nil {
				return err
			}
			awsProfile, err := cmd.Flags().GetString("aws-profile")
			if err != nil {
				return err
			}

			cfg, err := loadConfig()
			if err != nil {
				return err
			}

			if (target == gcpkms.Name || target == awskms.Name) && keyResourceID == "" {
				return fmt.Errorf("git vault migrate: --key-resource-id is required for provider %q", target)
			}

			targetCfg := config.Config{Provider: target, KeyResourceID: keyResourceID, AwsProfile: awsProfile}

			oldVault, oldRecipients, err := vaultForProvider(cfg)
			if err != nil {
				return fmt.Errorf("git vault migrate: %w", err)
			}
			newVault, newRecipients, err := vaultForProvider(targetCfg)
			if err != nil {
				return fmt.Errorf("git vault migrate: %w", err)
			}

			if len(oldRecipients) == 1 && len(newRecipients) == 1 && oldRecipients[0] == newRecipients[0] {
				return fmt.Errorf("git vault migrate: target is identical to the current key (%s); nothing to migrate", oldRecipients[0])
			}

			patterns, err := gitattr.Tracked(".gitattributes")
			if err != nil {
				return fmt.Errorf("git vault migrate: %w", err)
			}
			var files []string
			if len(patterns) > 0 {
				files, err = trackedFiles(patterns)
				if err != nil {
					return fmt.Errorf("git vault migrate: %w", err)
				}
			}

			for _, f := range files {
				if err := oldVault.Open(f); err != nil {
					return fmt.Errorf("git vault migrate: decrypt %s under %q: %w", f, cfg.Provider, err)
				}
				if err := newVault.Seal(f, newRecipients); err != nil {
					return fmt.Errorf("git vault migrate: re-seal %s under %q: %w", f, target, err)
				}
			}

			if err := config.Save(config.DefaultFileName, targetCfg); err != nil {
				return fmt.Errorf("git vault migrate: write %s: %w", config.DefaultFileName, err)
			}

			ui.New(cmd.OutOrStdout()).Info(fmt.Sprintf(
				"Migrated %d file(s) from %q to %q.\nWorking tree is now sealed under %q; run `git add -A && git commit` to finish — committed ciphertext still needs %q until you do.",
				len(files), cfg.Provider, target, target, cfg.Provider))
			return nil
		},
	}
	cmd.Flags().String("provider", "", "target key provider to migrate to (local, passphrase, gcpkms, awskms)")
	cmd.Flags().String("key-resource-id", "", "GCP KMS resource ID or AWS KMS ARN (required when --provider gcpkms or awskms)")
	cmd.Flags().String("aws-profile", "", "named AWS profile to use for credentials (awskms only)")
	return cmd
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/cli/... -v`
Expected: PASS (all tests in the package)

- [ ] **Step 5: Commit**

```bash
git add internal/cli/migrate.go internal/cli/migrate_test.go
git commit -m "feat(cli): support git vault migrate for awskms"
```

---

### Task 9: Documentation

**Files:**
- Create: `docs/awskms-provider.md`
- Modify: `README.md`

**Interfaces:**
- None (docs only) — no code depends on this task, and it depends on no earlier task's code (only on the CLI surface already being final, so flag names/messages quoted in the docs match Tasks 5–8).

- [ ] **Step 1: Write the doc**

Create `docs/awskms-provider.md`:

```markdown
# AWS KMS provider

git-vault's `awskms` provider authorizes encrypt/decrypt through an AWS
KMS key, using whatever AWS credentials the SDK's default credential
chain resolves on your machine — for most teams that means a named
profile set up with `aws configure sso` against your org's IAM Identity
Center (AWS SSO).

## 1. Admin bootstrap (one-time, done by whoever owns the AWS account)

    aws kms create-key --description "git-vault" \
      --tags TagKey=purpose,TagValue=git-vault

Note the `KeyId`/`Arn` printed in the output, or fetch it later:

    aws kms describe-key --key-id alias/git-vault --query KeyMetadata.Arn --output text

Grant the team access — either via a key policy statement naming an IAM
Identity Center permission set/role, or `kms:Encrypt`/`kms:Decrypt` in
that role's own IAM policy:

    aws kms create-grant --key-id <key-id> \
      --grantee-principal arn:aws:iam::<account>:role/<permission-set-role> \
      --operations Encrypt Decrypt

## 2. Per-repo setup

    git vault install --provider awskms \
      --key-resource-id arn:aws:kms:<region>:<account>:key/<key-id> \
      [--aws-profile <profile-name>]

This validates the ARN immediately with a real encrypt/decrypt round
trip — a typo'd ARN fails here, not at your first commit. `--aws-profile`
is optional; omit it to use the AWS SDK's default credential chain (env
vars, the default profile, or an instance role).

Add `--auto-login` to skip the confirmation prompt described below for
every developer on this repo. It's persisted to `.git-vault.yaml` as
`auto_login: true`, so it's a one-time, team-wide, repo-committed
decision (shared with gcpkms — see docs/gcpkms-provider.md).

## 3. Per-developer setup

    aws configure sso --profile <profile-name>   # one-time
    aws sso login --profile <profile-name>       # per session
    git vault login

`git vault login` checks whether the configured profile (or default
chain) already resolves to something that can use the configured key. If
the cached SSO session has expired or is missing, and `aws` is on your
PATH, it offers to run `aws sso login [--profile <profile-name>]` for
you (with confirmation — same as `--auto-login` above). Any other
failure (never ran `aws configure sso` yet, IAM denied, malformed ARN) is
surfaced as-is with a hint, since it isn't a single clean signal the way
an expired session is.

## 4. Rotation

Unlike GCP KMS, AWS KMS's automatic annual key rotation is fully
transparent — there's no key version to disable or destroy afterward;
Decrypt always works against whatever backing material originally
encrypted a given ciphertext, forever. Running `git vault rotate` still
re-seals every tracked file, forcing a fresh KMS `Encrypt` call:

    git vault rotate
    git add -A && git commit -m "Rotate git-vault key"

...but this is defense-in-depth re-encryption only, not a way to retire
old key material — AWS gives you no API to do that. If you actually need
to stop depending on specific key material (e.g. a suspected
compromise), create a new KMS key and use `git vault migrate` instead
(see below).

## Switching keys

To move to a different AWS KMS key (or a different provider entirely),
use `git vault migrate`, not `rotate`:

    git vault migrate --provider awskms \
      --key-resource-id arn:aws:kms:<region>:<account>:key/<new-key-id> \
      [--aws-profile <profile-name>]

## Troubleshooting

- `AccessDeniedException` — your role isn't granted
  `kms:Encrypt`/`kms:Decrypt` on the key. Ask whoever ran the admin
  bootstrap step to grant it.
- `no valid ARN found in '...'` — the `--key-resource-id` doesn't match
  `arn:aws:kms:<region>:<account>:key/<id>` (or `alias/<name>`). Copy it
  exactly from `aws kms describe-key`'s output.
- "awskms: AWS SSO session has expired or is invalid — run `aws sso
  login` first" — exactly that: the cached SSO token for this profile
  has expired or was never created; `git vault login` offers to fix it
  for you.
- Anything else (e.g. `aws configure sso` was never run for this
  profile) — the raw AWS SDK error is surfaced; run
  `aws configure sso --profile <profile-name>` once, then retry.
```

- [ ] **Step 2: Update README.md**

Replace this text (the "Status" paragraph):

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
GCP KMS and AWS KMS are available as team key-sharing providers,
authorized through your org's existing Google Workspace or AWS IAM
Identity Center SSO — see [docs/gcpkms-provider.md](docs/gcpkms-provider.md)
and [docs/awskms-provider.md](docs/awskms-provider.md). Azure is on the
roadmap.
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
[docs/gcpkms-provider.md](docs/gcpkms-provider.md) (Google Workspace SSO)
or [docs/awskms-provider.md](docs/awskms-provider.md) (AWS IAM Identity
Center / SSO).
```

- [ ] **Step 3: Verify the doc reads correctly**

Run: `cat docs/awskms-provider.md` and skim it end-to-end; run `grep -n "awskms\|AWS" README.md` to confirm both edits landed and no stale "on the roadmap" AWS mention remains.
Expected: `docs/awskms-provider.md` prints in full with no `TBD`; `README.md` no longer contains "(AWS, Azure) are on the roadmap".

- [ ] **Step 4: Commit**

```bash
git add docs/awskms-provider.md README.md
git commit -m "docs: add AWS KMS provider guide, link it from README"
```

---

### Task 10: Dependency tidy and full verification

**Files:**
- Modify: `go.mod`, `go.sum` (via `go mod tidy`, not hand-edited)

**Interfaces:**
- None — this is a whole-repo sanity pass after Tasks 1–9.

- [ ] **Step 1: Tidy go.mod**

Run: `go mod tidy`
Expected: exits 0; `git diff go.mod` shows `github.com/aws/aws-sdk-go-v2`, `github.com/aws/aws-sdk-go-v2/credentials`, and `github.com/aws/aws-sdk-go-v2/service/kms` (among others already indirect) move out of the `// indirect` block into the direct `require` block, or lose the `// indirect` marker in place. No new module should be added — these were already present as transitive dependencies.

- [ ] **Step 2: Run the full test suite**

Run: `go test ./...`
Expected: PASS, all packages, no skips other than the pre-existing Windows-only skip in `fakeGcloud`/`fakeAwsCLI`.

- [ ] **Step 3: Run the build and lint tasks**

Run: `task build`
Expected: builds `git-vault` binary with no errors.

Run: `task lint`
Expected: exits 0 (or matches whatever pre-existing lint baseline the repo has — do not introduce new findings).

- [ ] **Step 4: Manual smoke test against the real CLI**

```bash
cd "$(mktemp -d)" && git init -q
/path/to/git-vault install --provider awskms --key-resource-id not-a-real-arn
```

Expected: fails fast with `no valid ARN found in 'not-a-real-arn'` (real AWS SDK ARN parsing, no network call), and `git config --get filter.git-vault.clean` returns nothing (install didn't get past validation).

- [ ] **Step 5: Commit**

```bash
git add go.mod go.sum
git commit -m "chore: go mod tidy after adding the awskms provider"
```
