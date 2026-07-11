# GCP KMS Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `gcpkms`, git-vault's first team key-sharing / SSO-backed key provider, wired into `install`, `login`, `rotate`, and `migrate`.

**Architecture:** A thin `keyservice.Provider` adapter (`internal/keyservice/gcpkms`) wraps sops's existing `gcpkms.MasterKey`, authorized via whatever Google Application Default Credentials are active on the machine. `git vault login`/`install` verify a real KMS round trip instead of performing any OAuth flow themselves. `vaultForProvider` (internal/cli/vault.go) generalizes from a provider name to a full `config.Config` so gcpkms's resource ID flows through the same dispatch every other command already uses.

**Tech Stack:** Go 1.26, sops v3.13.2 (`github.com/getsops/sops/v3/gcpkms`), `cloud.google.com/go/kms` (already a transitive dependency), cobra, testify.

## Global Constraints

- Go version floor: 1.26.4 (go.mod) — do not lower it.
- sops is pinned at v3.13.2 (go.mod); `internal/vault.sopsVersion` must stay in sync with it — do not bump either without the other.
- No new external dependencies: everything gcpkms needs (`cloud.google.com/go/kms`, `google.golang.org/api`, `golang.org/x/oauth2`) is already a transitive dependency of sops v3.13.2 today (`// indirect` in go.mod) — this work only promotes existing indirect requires to direct via `go mod tidy`, it adds no new module.
- No shelling out to the `gcloud` CLI anywhere in git-vault — ADC is read via the Go client library only (spec non-goal).
- No new admin-bootstrap subcommand — KMS KeyRing/CryptoKey creation and IAM binding are documented `gcloud` commands in `docs/gcpkms-provider.md`, not git-vault code (spec non-goal).
- Follow existing provider package conventions exactly: a `Name` string const, a `New()` constructor, `Encrypt`/`Decrypt` matching `keyservice.Provider`, and a `SetXForTesting`-style seam for tests (see `passphrase.SetPromptForTesting` for the existing pattern).
- Every provider-dispatching CLI command (`install`, `login`, `rotate`, `migrate`) reads/writes `.git-vault.yaml` via `internal/config`, never anything else.

---

## Task 1: `internal/keyservice/gcpkms` — the Provider itself

**Files:**
- Create: `internal/keyservice/gcpkms/gcpkms.go`
- Create: `internal/keyservice/gcpkms/gcpkms_test.go`
- Create: `internal/keyservice/gcpkms/gcpkmstest/gcpkmstest.go`

**Interfaces:**
- Produces: `gcpkms.Name string` (= `"gcpkms"`); `gcpkms.New() Provider`; `gcpkms.Provider` satisfying `keyservice.Provider` (`Name() string`, `Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error)`, `Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error)`); `gcpkms.SetClientOptionsForTesting(opts []option.ClientOption) (restore func())`; `gcpkmstest.NewFakeServer() (opts []option.ClientOption, cleanup func(), err error)`. Every later task that touches GCP KMS imports these two packages.

- [ ] **Step 1: Write the fake KMS server test package**

`gcpkmstest` is a sibling package (like `net/http/httptest`) so both this package's own tests and every CLI test in later tasks can start a fake GCP KMS server without a real GCP project.

```go
// internal/keyservice/gcpkms/gcpkmstest/gcpkmstest.go

// Package gcpkmstest provides a fake GCP KMS server for testing code
// that uses internal/keyservice/gcpkms's Provider, without a real GCP
// project. It mirrors the pattern net/http/httptest uses for a fake HTTP
// server.
package gcpkmstest

import (
	"bytes"
	"context"
	"fmt"
	"net"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// marker prefixes every "ciphertext" this fake server produces, and is
// stripped back off on Decrypt — enough to prove real data flows through
// sops's gcpkms.MasterKey end-to-end without performing real
// cryptography or touching a real GCP project.
const marker = "fake-kms-wrapped:"

type fakeServer struct {
	kmspb.UnimplementedKeyManagementServiceServer
}

func (fakeServer) Encrypt(_ context.Context, req *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) {
	return &kmspb.EncryptResponse{Ciphertext: append([]byte(marker), req.GetPlaintext()...)}, nil
}

func (fakeServer) Decrypt(_ context.Context, req *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) {
	ciphertext := req.GetCiphertext()
	if !bytes.HasPrefix(ciphertext, []byte(marker)) {
		return nil, fmt.Errorf("gcpkmstest: ciphertext missing fake marker, got %q", ciphertext)
	}
	return &kmspb.DecryptResponse{Plaintext: ciphertext[len(marker):]}, nil
}

// NewFakeServer starts a fake GCP KMS gRPC server on a random local port
// and returns ClientOptions that redirect a gcpkms.MasterKey to it. The
// caller must invoke cleanup (e.g. via defer) to stop the server and
// close the client connection.
func NewFakeServer() (opts []option.ClientOption, cleanup func(), err error) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, fmt.Errorf("gcpkmstest: listen: %w", err)
	}
	srv := grpc.NewServer()
	kmspb.RegisterKeyManagementServiceServer(srv, fakeServer{})
	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		srv.Stop()
		return nil, nil, fmt.Errorf("gcpkmstest: dial: %w", err)
	}

	cleanup = func() {
		_ = conn.Close()
		srv.Stop()
	}
	return []option.ClientOption{option.WithGRPCConn(conn)}, cleanup, nil
}
```

- [ ] **Step 2: Write the Provider**

```go
// internal/keyservice/gcpkms/gcpkms.go

// Package gcpkms implements a keyservice.Provider backed by GCP Cloud
// KMS, authorized via whatever Google Application Default Credentials
// (ADC) are active on this machine — for most teams, that's already
// SSO'd through Google Workspace via `gcloud auth application-default
// login`. Unlike internal/keyservice/local and
// internal/keyservice/passphrase, git-vault holds no key material of its
// own here: GCP IAM on the KMS key is the only access control, and
// `git vault login` never performs its own OAuth flow. See
// docs/superpowers/specs/2026-07-11-gcpkms-provider-design.md.
package gcpkms

import (
	"context"
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

// friendlyLoginErr rewrites the fixed error golang.org/x/oauth2/google
// emits when Application Default Credentials can't be found anywhere in
// its default chain into an instruction to run the exact command that
// fixes it. There is no exported sentinel error for this case in the
// Google auth libraries, so a substring match on that fixed message is
// the same technique gcloud itself and most third-party tools use to
// detect it. Any other error (e.g. IAM permission denied, malformed
// resource ID) is wrapped with op but otherwise passed through as-is.
func friendlyLoginErr(op string, err error) error {
	if strings.Contains(err.Error(), "could not find default credentials") {
		return fmt.Errorf("gcpkms: no Google credentials found — run `gcloud auth application-default login` first")
	}
	return fmt.Errorf("gcpkms: %s: %w", op, err)
}
```

- [ ] **Step 3: Write the Provider's tests**

```go
// internal/keyservice/gcpkms/gcpkms_test.go
package gcpkms

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ducduyn31/git-vault/internal/keyservice/gcpkms/gcpkmstest"
)

const testResourceID = "projects/test/locations/global/keyRings/test/cryptoKeys/test"

func TestProvider_EncryptDecrypt_RoundTrip(t *testing.T) {
	opts, cleanup, err := gcpkmstest.NewFakeServer()
	require.NoError(t, err)
	defer cleanup()
	restore := SetClientOptionsForTesting(opts)
	defer restore()

	p := New()
	require.Equal(t, Name, p.Name())

	ciphertext, err := p.Encrypt(context.Background(), testResourceID, []byte("sops data key"))
	require.NoError(t, err)
	require.NotEqual(t, "sops data key", string(ciphertext))

	plaintext, err := p.Decrypt(context.Background(), testResourceID, ciphertext)
	require.NoError(t, err)
	require.Equal(t, "sops data key", string(plaintext))
}

func TestProvider_Decrypt_TamperedCiphertextFails(t *testing.T) {
	opts, cleanup, err := gcpkmstest.NewFakeServer()
	require.NoError(t, err)
	defer cleanup()
	restore := SetClientOptionsForTesting(opts)
	defer restore()

	p := New()
	_, err = p.Decrypt(context.Background(), testResourceID, []byte("not a real wrapped key"))
	require.Error(t, err)
}

func TestProvider_Encrypt_InvalidResourceIDFails(t *testing.T) {
	p := New()
	_, err := p.Encrypt(context.Background(), "not-a-resource-id", []byte("data"))
	require.ErrorContains(t, err, "no valid resource ID")
}

func TestFriendlyLoginErr_RewritesMissingADCMessage(t *testing.T) {
	err := friendlyLoginErr("encrypt", errors.New("google: could not find default credentials. See https://example.com for more information"))
	require.ErrorContains(t, err, "gcloud auth application-default login")
}

func TestFriendlyLoginErr_PassesThroughOtherErrors(t *testing.T) {
	err := friendlyLoginErr("encrypt", errors.New("permission denied"))
	require.ErrorContains(t, err, "gcpkms: encrypt: permission denied")
}
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `go test ./internal/keyservice/gcpkms/... -v`
Expected: FAIL — package doesn't build yet (files don't exist until Step 1/2 are saved). Once Steps 1-3 are all saved, re-run before Step 5 to confirm a clean starting point isn't silently already passing for the wrong reason (it can't be, since the files are new).

- [ ] **Step 5: Update go.mod/go.sum**

Run: `go mod tidy`
Expected: `cloud.google.com/go/kms`, `google.golang.org/api`, and their transitive requirements move from `// indirect` to direct requires in `go.mod` (or stay, if `go mod tidy` decides sops's own import already covers directness — either way the command must exit 0 with no manual edits needed).

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./internal/keyservice/gcpkms/... -v`
Expected: PASS, all 5 tests.

- [ ] **Step 7: Commit**

```bash
git add internal/keyservice/gcpkms go.mod go.sum
git commit -m "feat: add GCP KMS key provider"
```

---

## Task 2: `internal/config` — add `KeyResourceID`

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces: `config.Config.KeyResourceID string`. Every later task that builds or reads a gcpkms-flavored `.git-vault.yaml` relies on this field.

- [ ] **Step 1: Update the round-trip test to cover the new field**

```go
// internal/config/config_test.go — replace TestSaveLoad_RoundTrip's `want`
func TestSaveLoad_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".git-vault.yaml")
	want := Config{
		Provider:      "gcpkms",
		IssuerURL:     "https://issuer.example.com",
		ClientID:      "git-vault-cli",
		KeyResourceID: "projects/p/locations/global/keyRings/r/cryptoKeys/k",
	}

	require.NoError(t, Save(path, want))

	got, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, want, got)
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/config/... -run TestSaveLoad_RoundTrip -v`
Expected: FAIL — `unknown field KeyResourceID in struct literal of type Config` (compile error).

- [ ] **Step 3: Add the field**

```go
// internal/config/config.go
type Config struct {
	Provider      string `yaml:"provider"`
	IssuerURL     string `yaml:"issuer_url,omitempty"`
	ClientID      string `yaml:"client_id,omitempty"`
	KeyResourceID string `yaml:"key_resource_id,omitempty"`
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/config/... -v`
Expected: PASS, all tests including `TestSaveLoad_RoundTrip`.

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat: add KeyResourceID to git-vault config"
```

---

## Task 3: Generalize `vaultForProvider` to take full config

**Files:**
- Modify: `internal/cli/vault.go`
- Modify: `internal/cli/vault_test.go`
- Modify: `internal/cli/install.go` (call-site only, no new flags yet — that's Task 5)
- Modify: `internal/cli/rotate.go` (call-site only, no new case yet — that's Task 6)
- Modify: `internal/cli/migrate.go` (call-site only, no new flags yet — that's Task 7)

**Interfaces:**
- Consumes: `gcpkms.Name`, `gcpkms.New()` (Task 1); `config.Config.KeyResourceID` (Task 2).
- Produces: `vaultForProvider(cfg config.Config) (*vault.Vault, []string, error)` (signature changed from `vaultForProvider(name string)`); `newGCPKMSVault(cfg config.Config) (*vault.Vault, []string, error)`. Every later task's CLI-layer changes call `vaultForProvider` with a `config.Config`, never a bare string, from here on.

This task is a signature refactor across the package, not new behavior — every existing test must still pass unchanged in outcome, only in how they call `vaultForProvider`.

- [ ] **Step 1: Update `vault_test.go` to the new signature, and add a gcpkms case**

```go
// internal/cli/vault_test.go — replace both vaultForProvider calls, add one test
package cli

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/keyservice/gcpkms"
	"github.com/ducduyn31/git-vault/internal/keyservice/gcpkms/gcpkmstest"
	"github.com/ducduyn31/git-vault/internal/keyservice/passphrase"
)

func TestNewLocalVault_ReturnsVaultAndRecipient(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	v, recipients, err := newLocalVault()
	require.NoError(t, err)
	require.NotNil(t, v)
	require.Len(t, recipients, 1)
	require.True(t, strings.HasPrefix(recipients[0], "local:"))
}

func TestVaultForProvider_Passphrase(t *testing.T) {
	t.Setenv(passphrase.EnvVar, "correct horse battery staple")

	v, recipients, err := vaultForProvider(config.Config{Provider: passphrase.Name})
	require.NoError(t, err)
	require.NotNil(t, v)
	require.Equal(t, []string{"passphrase:shared"}, recipients)
}

func TestVaultForProvider_GCPKMS(t *testing.T) {
	opts, cleanup, err := gcpkmstest.NewFakeServer()
	require.NoError(t, err)
	defer cleanup()
	restore := gcpkms.SetClientOptionsForTesting(opts)
	defer restore()

	v, recipients, err := vaultForProvider(config.Config{
		Provider:      gcpkms.Name,
		KeyResourceID: "projects/test/locations/global/keyRings/test/cryptoKeys/test",
	})
	require.NoError(t, err)
	require.NotNil(t, v)
	require.Equal(t, []string{"gcpkms:projects/test/locations/global/keyRings/test/cryptoKeys/test"}, recipients)
}

func TestVaultForProvider_UnknownProviderFails(t *testing.T) {
	_, _, err := vaultForProvider(config.Config{Provider: "bogus"})
	require.ErrorContains(t, err, `unknown provider "bogus"`)
}

func TestNewVault_MissingConfigFails(t *testing.T) {
	chdirTemp(t)

	_, _, err := newVault()
	require.ErrorContains(t, err, "git vault install")
}

func TestNewVault_ReadsProviderFromConfig(t *testing.T) {
	chdirTemp(t)
	t.Setenv(passphrase.EnvVar, "correct horse battery staple")
	require.NoError(t, config.Save(config.DefaultFileName, config.Config{Provider: passphrase.Name}))

	v, recipients, err := newVault()
	require.NoError(t, err)
	require.NotNil(t, v)
	require.Equal(t, []string{"passphrase:shared"}, recipients)
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/cli/... -run TestVaultForProvider -v`
Expected: FAIL — compile error, `vaultForProvider(config.Config{...})` doesn't match `func vaultForProvider(name string)`.

- [ ] **Step 3: Update `vault.go`**

```go
// internal/cli/vault.go
package cli

import (
	"fmt"
	"os"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/keyservice"
	"github.com/ducduyn31/git-vault/internal/keyservice/gcpkms"
	"github.com/ducduyn31/git-vault/internal/keyservice/local"
	"github.com/ducduyn31/git-vault/internal/keyservice/passphrase"
	"github.com/ducduyn31/git-vault/internal/vault"
)

func newLocalVault() (*vault.Vault, []string, error) {
	provider, err := local.New()
	if err != nil {
		return nil, nil, err
	}

	registry := keyservice.NewRegistry()
	if err := registry.Register(provider); err != nil {
		return nil, nil, err
	}
	server := keyservice.NewServer(registry)

	recipient, err := provider.Recipient()
	if err != nil {
		return nil, nil, err
	}

	return vault.New(server), []string{local.Name + ":" + recipient}, nil
}

func newPassphraseVault() (*vault.Vault, []string, error) {
	provider := passphrase.New()

	registry := keyservice.NewRegistry()
	if err := registry.Register(provider); err != nil {
		return nil, nil, err
	}
	server := keyservice.NewServer(registry)

	return vault.New(server), []string{passphrase.Name + ":" + passphrase.KeyID}, nil
}

// newGCPKMSVault builds a Vault dispatching to GCP KMS, along with the
// "<provider>:<key-id>" recipient string for cfg.KeyResourceID. Unlike
// local/passphrase, the key material lives entirely in GCP — this
// Provider holds no identity of its own beyond whatever ADC resolves to.
func newGCPKMSVault(cfg config.Config) (*vault.Vault, []string, error) {
	registry := keyservice.NewRegistry()
	if err := registry.Register(gcpkms.New()); err != nil {
		return nil, nil, err
	}
	server := keyservice.NewServer(registry)

	return vault.New(server), []string{gcpkms.Name + ":" + cfg.KeyResourceID}, nil
}

// vaultForProvider builds the Vault for the provider named in cfg. It
// takes the full config, not just the provider name, because gcpkms
// needs KeyResourceID — local/passphrase ignore everything but
// cfg.Provider.
func vaultForProvider(cfg config.Config) (*vault.Vault, []string, error) {
	switch cfg.Provider {
	case local.Name:
		return newLocalVault()
	case passphrase.Name:
		return newPassphraseVault()
	case gcpkms.Name:
		return newGCPKMSVault(cfg)
	default:
		return nil, nil, fmt.Errorf("git vault: unknown provider %q in %s", cfg.Provider, config.DefaultFileName)
	}
}

// loadConfig reads .git-vault.yaml, wrapping a missing file with a hint
// to run `git vault install` instead of surfacing a raw os.PathError.
func loadConfig() (config.Config, error) {
	cfg, err := config.Load(config.DefaultFileName)
	if err != nil {
		if os.IsNotExist(err) {
			return config.Config{}, fmt.Errorf("git vault: no %s found, run \"git vault install\" first", config.DefaultFileName)
		}
		return config.Config{}, fmt.Errorf("git vault: read %s: %w", config.DefaultFileName, err)
	}
	return cfg, nil
}

// newVault loads .git-vault.yaml and builds the Vault for whichever
// provider it names. Every command that seals or opens a file (encrypt,
// decrypt, clean, smudge) shares this instead of repeating the
// config/registry/server wiring.
func newVault() (*vault.Vault, []string, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, nil, err
	}
	return vaultForProvider(cfg)
}
```

- [ ] **Step 4: Update the three call sites so the package compiles**

In `internal/cli/install.go`, change:
```go
_, recipients, err := vaultForProvider(providerName)
```
to:
```go
_, recipients, err := vaultForProvider(config.Config{Provider: providerName})
```

In `internal/cli/rotate.go`, change:
```go
oldVault, _, err := vaultForProvider(cfg.Provider)
```
to:
```go
oldVault, _, err := vaultForProvider(cfg)
```
and change:
```go
newVault, newRecipients, err = vaultForProvider(local.Name)
```
to:
```go
newVault, newRecipients, err = vaultForProvider(config.Config{Provider: local.Name})
```

In `internal/cli/migrate.go`, change:
```go
oldVault, _, err := vaultForProvider(cfg.Provider)
```
to:
```go
oldVault, _, err := vaultForProvider(cfg)
```
and change:
```go
newVault, newRecipients, err := vaultForProvider(target)
```
to:
```go
newVault, newRecipients, err := vaultForProvider(config.Config{Provider: target})
```

- [ ] **Step 5: Run the full test suite to verify everything still passes**

Run: `go test ./... -v`
Expected: PASS, every existing test plus the three new/updated ones in `vault_test.go`.

- [ ] **Step 6: Commit**

```bash
git add internal/cli/vault.go internal/cli/vault_test.go internal/cli/install.go internal/cli/rotate.go internal/cli/migrate.go
git commit -m "refactor: vaultForProvider takes full config, add gcpkms dispatch"
```

---

## Task 4: `git vault login` — real implementation

**Files:**
- Modify: `internal/cli/login.go`
- Modify: `internal/cli/root_test.go` (remove the now-stale stub assertion)
- Create: `internal/cli/login_test.go`

**Interfaces:**
- Consumes: `vaultForProvider`'s config-based signature is not needed here — login talks to `gcpkms.Provider` directly (it's verifying auth, not building a Vault). Consumes `gcpkms.Name`, `gcpkms.New()`, `gcpkms.SetClientOptionsForTesting` (Task 1); `config.Config.KeyResourceID` (Task 2).
- Produces: `verifyGCPKMSRoundTrip(ctx context.Context, keyResourceID string) error` (unexported, package `cli`) — Task 5's `install.go` change calls this too.

- [ ] **Step 1: Delete the stale stub test and write login's tests**

In `internal/cli/root_test.go`, delete the entire `TestStubCommands_NotImplemented` function — `login` is no longer a stub, and it was the only case in that table.

```go
// internal/cli/login_test.go
package cli

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/keyservice/gcpkms"
	"github.com/ducduyn31/git-vault/internal/keyservice/gcpkms/gcpkmstest"
	"github.com/ducduyn31/git-vault/internal/keyservice/local"
)

func TestLoginCmd_GCPKMS_Succeeds(t *testing.T) {
	chdirTemp(t)
	require.NoError(t, config.Save(config.DefaultFileName, config.Config{
		Provider:      gcpkms.Name,
		KeyResourceID: "projects/test/locations/global/keyRings/test/cryptoKeys/test",
	}))

	opts, cleanup, err := gcpkmstest.NewFakeServer()
	require.NoError(t, err)
	defer cleanup()
	restore := gcpkms.SetClientOptionsForTesting(opts)
	defer restore()

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{"login"})
	require.NoError(t, cmd.Execute())
	require.Contains(t, out.String(), "authorized")
}

func TestLoginCmd_GCPKMS_FailsWithoutReachableKMS(t *testing.T) {
	chdirTemp(t)
	require.NoError(t, config.Save(config.DefaultFileName, config.Config{
		Provider:      gcpkms.Name,
		KeyResourceID: "projects/test/locations/global/keyRings/test/cryptoKeys/test",
	}))

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"login"})
	require.Error(t, cmd.Execute())
}

func TestLoginCmd_LocalProviderRejected(t *testing.T) {
	chdirTemp(t)
	require.NoError(t, config.Save(config.DefaultFileName, config.Config{Provider: local.Name}))

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"login"})

	err := cmd.Execute()
	require.ErrorContains(t, err, "does not use git vault login")
}

func TestLoginCmd_MissingConfigFails(t *testing.T) {
	chdirTemp(t)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"login"})

	err := cmd.Execute()
	require.ErrorContains(t, err, "git vault install")
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/cli/... -run TestLoginCmd -v`
Expected: FAIL — `login` still returns `"not implemented in scaffold"` for every case.

- [ ] **Step 3: Implement `login.go`**

```go
// internal/cli/login.go
package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/keyservice/gcpkms"
)

// gcpkmsLoginProbe is the fixed plaintext used to verify a GCP KMS round
// trip. It carries no meaning beyond needing to survive
// Encrypt-then-Decrypt unchanged.
const gcpkmsLoginProbe = "git-vault-login-check"

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

			if cfg.Provider != gcpkms.Name {
				return fmt.Errorf("git vault login: provider %q does not use git vault login", cfg.Provider)
			}

			if err := verifyGCPKMSRoundTrip(cmd.Context(), cfg.KeyResourceID); err != nil {
				return fmt.Errorf("git vault login: %w", err)
			}

			_, err = fmt.Fprintln(cmd.OutOrStdout(), "GCP KMS round trip succeeded — this machine is authorized.")
			return err
		},
	}
}

// verifyGCPKMSRoundTrip encrypts and decrypts a fixed probe value against
// keyResourceID, returning an error (from gcpkms.Provider — see its
// friendlyLoginErr) if ADC is missing, IAM denies access, or the resource
// ID is malformed. Used by both `git vault login` and `git vault install`
// (to fail fast on a typo'd --key-resource-id).
func verifyGCPKMSRoundTrip(ctx context.Context, keyResourceID string) error {
	provider := gcpkms.New()
	ciphertext, err := provider.Encrypt(ctx, keyResourceID, []byte(gcpkmsLoginProbe))
	if err != nil {
		return err
	}
	plaintext, err := provider.Decrypt(ctx, keyResourceID, ciphertext)
	if err != nil {
		return err
	}
	if string(plaintext) != gcpkmsLoginProbe {
		return fmt.Errorf("gcpkms: round trip returned unexpected plaintext")
	}
	return nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/cli/... -v`
Expected: PASS, all tests including the four new `login_test.go` cases, and `root_test.go` with the stale case removed.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/login.go internal/cli/login_test.go internal/cli/root_test.go
git commit -m "feat: implement git vault login for the gcpkms provider"
```

---

## Task 5: `git vault install` — gcpkms support

**Files:**
- Modify: `internal/cli/install.go`
- Modify: `internal/cli/install_test.go`

**Interfaces:**
- Consumes: `verifyGCPKMSRoundTrip` (Task 4); `vaultForProvider(cfg config.Config)` (Task 3); `gcpkms.Name` (Task 1).
- Produces: `--key-resource-id` flag on `install`. Task 7's `migrate.go` adds the identical flag independently (they don't share a helper — each command's flag registration is local to that command, same as the existing `--provider` flag).

- [ ] **Step 1: Write install's gcpkms tests**

```go
// internal/cli/install_test.go — add below the existing tests, add imports
// for "github.com/ducduyn31/git-vault/internal/keyservice/gcpkms" and
// ".../gcpkms/gcpkmstest"

func TestInstallCmd_GCPKMS_WritesConfigAndValidates(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	opts, cleanup, err := gcpkmstest.NewFakeServer()
	require.NoError(t, err)
	defer cleanup()
	restore := gcpkms.SetClientOptionsForTesting(opts)
	defer restore()

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{
		"install", "--provider=" + gcpkms.Name,
		"--key-resource-id=projects/test/locations/global/keyRings/test/cryptoKeys/test",
	})
	require.NoError(t, cmd.Execute())

	require.Contains(t, out.String(), "Recipient: gcpkms:projects/test/locations/global/keyRings/test/cryptoKeys/test")

	cfg, err := config.Load(config.DefaultFileName)
	require.NoError(t, err)
	require.Equal(t, gcpkms.Name, cfg.Provider)
	require.Equal(t, "projects/test/locations/global/keyRings/test/cryptoKeys/test", cfg.KeyResourceID)
}

func TestInstallCmd_GCPKMS_MissingKeyResourceIDFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"install", "--provider=" + gcpkms.Name})

	err := cmd.Execute()
	require.ErrorContains(t, err, "--key-resource-id is required")
}

func TestInstallCmd_GCPKMS_FailsWithoutReachableKMS(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"install", "--provider=" + gcpkms.Name,
		"--key-resource-id=projects/test/locations/global/keyRings/test/cryptoKeys/test",
	})

	err := cmd.Execute()
	require.Error(t, err)

	_, gitErr := exec.Command("git", "config", "--get", "filter.git-vault.clean").Output()
	require.Error(t, gitErr, "git config must not be set when install fails the KMS round trip")
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/cli/... -run TestInstallCmd_GCPKMS -v`
Expected: FAIL — no `--key-resource-id` flag exists yet (`unknown flag` error) and `gcpkms` isn't accepted as a provider.

- [ ] **Step 3: Implement the flag and validation in `install.go`**

```go
// internal/cli/install.go
package cli

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/keyservice/gcpkms"
	"github.com/ducduyn31/git-vault/internal/keyservice/local"
	"github.com/ducduyn31/git-vault/internal/keyservice/passphrase"
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

			if providerName == passphrase.Name && os.Getenv(passphrase.EnvVar) == "" {
				return fmt.Errorf("git vault install: %s not set", passphrase.EnvVar)
			}
			if providerName == gcpkms.Name && keyResourceID == "" {
				return fmt.Errorf("git vault install: --key-resource-id is required for provider %q", gcpkms.Name)
			}

			cfg := config.Config{Provider: providerName, KeyResourceID: keyResourceID}

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

			if providerName == gcpkms.Name {
				if err := verifyGCPKMSRoundTrip(cmd.Context(), keyResourceID); err != nil {
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
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Installed git-vault filter driver (%s scope).\nRecipient: %s\n", scope, recipient); err != nil {
				return fmt.Errorf("git vault install: print recipient: %w", err)
			}
			return nil
		},
	}
	cmd.Flags().Bool("global", false, "install the filter driver in the user's global git config")
	cmd.Flags().String("provider", local.Name, "key provider to use (local, passphrase, gcpkms)")
	cmd.Flags().String("key-resource-id", "", "GCP KMS resource ID (required when --provider gcpkms)")
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

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/cli/... -v`
Expected: PASS, all tests including the three new `TestInstallCmd_GCPKMS_*` cases.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/install.go internal/cli/install_test.go
git commit -m "feat: add gcpkms support to git vault install"
```

---

## Task 6: `git vault rotate` — gcpkms support

**Files:**
- Modify: `internal/cli/rotate.go`
- Modify: `internal/cli/install_test.go` (split `setupTrackedEncryptedFile` into a config-based helper)
- Modify: `internal/cli/rotate_test.go`

**Interfaces:**
- Consumes: `vaultForProvider(cfg config.Config)` (Task 3); `gcpkms.Name`, `gcpkms.SetClientOptionsForTesting` (Task 1).
- Produces: `setupTrackedEncryptedFileWithConfig(t *testing.T, cfg config.Config) string` (test helper) — Task 7's `migrate_test.go` reuses this.

- [ ] **Step 1: Split the test helper and write rotate's gcpkms test**

```go
// internal/cli/install_test.go — replace setupTrackedEncryptedFile with:

// setupTrackedEncryptedFile writes .git-vault.yaml directly (not via
// runInstall — install also sets filter.git-vault.* git config pointing at
// a real git-vault binary that isn't built under `go test`, which would
// make the "git add" below try to invoke it), tracks "secret.yaml", writes
// and git-adds it, then encrypts it under the given provider. Returns the
// plaintext it started from.
func setupTrackedEncryptedFile(t *testing.T, provider string) string {
	t.Helper()
	return setupTrackedEncryptedFileWithConfig(t, config.Config{Provider: provider})
}

// setupTrackedEncryptedFileWithConfig is setupTrackedEncryptedFile, but
// for providers (e.g. gcpkms) that need more than just a provider name
// persisted to .git-vault.yaml.
func setupTrackedEncryptedFileWithConfig(t *testing.T, cfg config.Config) string {
	t.Helper()
	require.NoError(t, config.Save(config.DefaultFileName, cfg))

	trackCmd := NewRootCmd()
	trackCmd.SetOut(&bytes.Buffer{})
	trackCmd.SetArgs([]string{"track", "secret.yaml"})
	require.NoError(t, trackCmd.Execute())

	original := "password: hunter2\n"
	require.NoError(t, os.WriteFile("secret.yaml", []byte(original), 0o644))
	require.NoError(t, exec.Command("git", "add", "secret.yaml").Run())

	encryptCmd := NewRootCmd()
	encryptCmd.SetOut(&bytes.Buffer{})
	encryptCmd.SetArgs([]string{"encrypt", "secret.yaml"})
	require.NoError(t, encryptCmd.Execute())

	return original
}
```

```go
// internal/cli/rotate_test.go — add below the existing tests, add imports
// for "github.com/ducduyn31/git-vault/internal/keyservice/gcpkms" and
// ".../gcpkms/gcpkmstest"

func TestRotateCmd_GCPKMS_RoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	opts, cleanup, err := gcpkmstest.NewFakeServer()
	require.NoError(t, err)
	defer cleanup()
	restore := gcpkms.SetClientOptionsForTesting(opts)
	defer restore()

	original := setupTrackedEncryptedFileWithConfig(t, config.Config{
		Provider:      gcpkms.Name,
		KeyResourceID: "projects/test/locations/global/keyRings/test/cryptoKeys/test",
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

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/cli/... -run TestRotateCmd_GCPKMS -v`
Expected: FAIL — `rotate` on provider `gcpkms` hits the `default:` case, `"rotation not supported for provider"`.

- [ ] **Step 3: Add the gcpkms case to `rotate.go`**

Add the import `"github.com/ducduyn31/git-vault/internal/keyservice/gcpkms"`, then add this case to both switches:

```go
// internal/cli/rotate.go — in the first switch (building newVault/newRecipients), add:
case gcpkms.Name:
	// The resource ID never changes across a GCP-side rotation — only
	// which key version is primary does, invisible to git-vault.
	// Re-sealing every file forces a fresh KMS Encrypt call, which GCP
	// always services with the current primary version, moving every
	// file's wrapped data key off whatever version it was on before.
	newVault, newRecipients, err = vaultForProvider(cfg)
	if err != nil {
		return fmt.Errorf("git vault rotate: %w", err)
	}
	oldVault = newVault
```

```go
// internal/cli/rotate.go — in the second switch (building followUp), add:
case gcpkms.Name:
	followUp = "Old KMS key versions are still enabled to decrypt anything not yet migrated, including committed history. Once every commit that matters has been rotated, disable or destroy the old version(s) in GCP to complete the rotation."
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/cli/... -v`
Expected: PASS, all tests including `TestRotateCmd_GCPKMS_RoundTrip`.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/rotate.go internal/cli/install_test.go internal/cli/rotate_test.go
git commit -m "feat: add gcpkms support to git vault rotate"
```

---

## Task 7: `git vault migrate` — gcpkms support and the recipient-comparison fix

**Files:**
- Modify: `internal/cli/migrate.go`
- Modify: `internal/cli/migrate_test.go`

**Interfaces:**
- Consumes: `setupTrackedEncryptedFileWithConfig` (Task 6); `vaultForProvider(cfg config.Config)` (Task 3); `gcpkms.Name`, `gcpkms.SetClientOptionsForTesting` (Task 1).
- Produces: nothing new for later tasks — this is the last CLI command in the plan.

Building both vaults before the "nothing to do" check means, for the `local` provider specifically, migrate may now generate a first identity file as a side effect of the check itself if none existed yet — same as any other operation touching a local vault. Harmless, but worth knowing: it's a minor behavior change from today's immediate fail-fast on provider-name match.

- [ ] **Step 1: Update the existing same-provider test and add gcpkms tests**

```go
// internal/cli/migrate_test.go — replace TestMigrateCmd_SameProviderFails's assertion
func TestMigrateCmd_SameProviderFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	setupTrackedEncryptedFile(t, local.Name)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"migrate", "--provider=" + local.Name})

	err := cmd.Execute()
	require.ErrorContains(t, err, "identical to the current key")

	cfg, err := config.Load(config.DefaultFileName)
	require.NoError(t, err)
	require.Equal(t, local.Name, cfg.Provider)
}
```

```go
// internal/cli/migrate_test.go — add below the existing tests, add imports
// for "github.com/ducduyn31/git-vault/internal/keyservice/gcpkms" and
// ".../gcpkms/gcpkmstest"

func TestMigrateCmd_GCPKMSToGCPKMS_DifferentKey_RoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	opts, cleanup, err := gcpkmstest.NewFakeServer()
	require.NoError(t, err)
	defer cleanup()
	restore := gcpkms.SetClientOptionsForTesting(opts)
	defer restore()

	original := setupTrackedEncryptedFileWithConfig(t, config.Config{
		Provider:      gcpkms.Name,
		KeyResourceID: "projects/test/locations/global/keyRings/test/cryptoKeys/key-a",
	})

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{
		"migrate", "--provider=" + gcpkms.Name,
		"--key-resource-id=projects/test/locations/global/keyRings/test/cryptoKeys/key-b",
	})
	require.NoError(t, cmd.Execute())
	require.Contains(t, out.String(), "Migrated 1 file")

	cfg, err := config.Load(config.DefaultFileName)
	require.NoError(t, err)
	require.Equal(t, gcpkms.Name, cfg.Provider)
	require.Equal(t, "projects/test/locations/global/keyRings/test/cryptoKeys/key-b", cfg.KeyResourceID)

	decryptCmd := NewRootCmd()
	decryptCmd.SetOut(&bytes.Buffer{})
	decryptCmd.SetArgs([]string{"decrypt", "secret.yaml"})
	require.NoError(t, decryptCmd.Execute())

	opened, err := os.ReadFile("secret.yaml")
	require.NoError(t, err)
	require.Equal(t, original, string(opened))
}

func TestMigrateCmd_GCPKMSToGCPKMS_SameKeyFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	opts, cleanup, err := gcpkmstest.NewFakeServer()
	require.NoError(t, err)
	defer cleanup()
	restore := gcpkms.SetClientOptionsForTesting(opts)
	defer restore()

	setupTrackedEncryptedFileWithConfig(t, config.Config{
		Provider:      gcpkms.Name,
		KeyResourceID: "projects/test/locations/global/keyRings/test/cryptoKeys/key-a",
	})

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"migrate", "--provider=" + gcpkms.Name,
		"--key-resource-id=projects/test/locations/global/keyRings/test/cryptoKeys/key-a",
	})
	err = cmd.Execute()
	require.ErrorContains(t, err, "identical to the current key")
}

func TestMigrateCmd_GCPKMSTarget_MissingKeyResourceIDFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	setupTrackedEncryptedFile(t, local.Name)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"migrate", "--provider=" + gcpkms.Name})

	err := cmd.Execute()
	require.ErrorContains(t, err, "--key-resource-id is required")
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/cli/... -run TestMigrateCmd -v`
Expected: FAIL — `TestMigrateCmd_SameProviderFails` fails on the new assertion text; the three new gcpkms tests fail (`unknown flag: --key-resource-id`, `unknown provider "gcpkms"`).

- [ ] **Step 3: Implement the flag, targetCfg, and recipient-comparison fix in `migrate.go`**

```go
// internal/cli/migrate.go
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/gitattr"
	"github.com/ducduyn31/git-vault/internal/keyservice/gcpkms"
	"github.com/ducduyn31/git-vault/internal/keyservice/passphrase"
)

// newMigrateCmd re-seals every tracked file from the repo's current
// provider/key to a different target, then updates .git-vault.yaml. A
// target that resolves to the exact same key as the current one is
// rejected rather than silently no-op'd: for local/passphrase that's
// always true (each has exactly one key source); for gcpkms it's only
// true when the resource ID also matches, since two different gcpkms
// targets can share the provider name but name different keys. See
// docs/superpowers/specs/2026-07-11-migrate-provider-design.md and
// docs/superpowers/specs/2026-07-11-gcpkms-provider-design.md.
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

			cfg, err := loadConfig()
			if err != nil {
				return err
			}

			if target == passphrase.Name && os.Getenv(passphrase.EnvVar) == "" {
				return fmt.Errorf("git vault migrate: %s not set", passphrase.EnvVar)
			}
			if target == gcpkms.Name && keyResourceID == "" {
				return fmt.Errorf("git vault migrate: --key-resource-id is required for provider %q", gcpkms.Name)
			}

			targetCfg := config.Config{Provider: target, KeyResourceID: keyResourceID}

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

			_, err = fmt.Fprintf(cmd.OutOrStdout(),
				"Migrated %d file(s) from %q to %q.\nWorking tree is now sealed under %q; run `git add -A && git commit` to finish — committed ciphertext still needs %q until you do.\n",
				len(files), cfg.Provider, target, target, cfg.Provider)
			if err != nil {
				return fmt.Errorf("git vault migrate: print summary: %w", err)
			}
			return nil
		},
	}
	cmd.Flags().String("provider", "", "target key provider to migrate to (local, passphrase, gcpkms)")
	cmd.Flags().String("key-resource-id", "", "GCP KMS resource ID (required when --provider gcpkms)")
	return cmd
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/cli/... -v`
Expected: PASS, all tests including the updated `TestMigrateCmd_SameProviderFails` and the three new gcpkms tests.

- [ ] **Step 5: Run the entire test suite**

Run: `go test ./... -v`
Expected: PASS, every test in the module.

- [ ] **Step 6: Commit**

```bash
git add internal/cli/migrate.go internal/cli/migrate_test.go
git commit -m "feat: add gcpkms support to git vault migrate"
```

---

## Task 8: User-facing docs

**Files:**
- Create: `docs/gcpkms-provider.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: the final flag/command shapes from Tasks 4-7 (`--key-resource-id`, `git vault login`, `git vault rotate`, `git vault migrate`).
- Produces: nothing consumed by other tasks — this is the last task in the plan.

This task has no tests to write — it's documentation. Verification is a manual read-through against the actual command behavior implemented in Tasks 4-7.

- [ ] **Step 1: Write `docs/gcpkms-provider.md`**

```markdown
# GCP KMS provider

git-vault's `gcpkms` provider authorizes encrypt/decrypt through a GCP
KMS key, using whatever Google credentials are already active on your
machine — Application Default Credentials (ADC). For most teams that
means whatever your org's Google Workspace SSO already set up.

## 1. Admin bootstrap (one-time, done by whoever owns the GCP project)

    gcloud kms keyrings create git-vault \
      --location=global

    gcloud kms keys create git-vault-key \
      --location=global \
      --keyring=git-vault \
      --purpose=encryption

    gcloud kms keys add-iam-policy-binding git-vault-key \
      --location=global \
      --keyring=git-vault \
      --member="group:engineering@example.com" \
      --role="roles/cloudkms.cryptoKeyEncrypterDecrypter"

Note the full resource ID (printed by `gcloud kms keys create`, or built
yourself):

    projects/<project>/locations/global/keyRings/git-vault/cryptoKeys/git-vault-key

## 2. Per-repo setup

    git vault install --provider gcpkms \
      --key-resource-id projects/<project>/locations/global/keyRings/git-vault/cryptoKeys/git-vault-key

This validates the resource ID immediately with a real encrypt/decrypt
round trip — a typo'd path fails here, not at your first commit.

## 3. Per-developer setup

    gcloud auth application-default login
    git vault login

`git vault login` doesn't perform the browser flow itself — it only
checks whether ADC already resolves to something that can use the
configured key, and tells you the exact command to run if not.

## 4. Rotation

GCP's automatic key rotation only keeps old key versions passively
decryptable — it never lets you retire one. Run `git vault rotate`
periodically (or after a suspected key exposure) to force every tracked
file's wrapped data key onto the current primary key version:

    git vault rotate
    git add -A && git commit -m "Rotate git-vault key"

Once every commit that matters has gone through a rotation, the old
version(s) can be safely disabled or destroyed:

    gcloud kms keys versions disable <version> \
      --location=global --keyring=git-vault --key=git-vault-key
    gcloud kms keys versions destroy <version> \
      --location=global --keyring=git-vault --key=git-vault-key

## Switching keys

To move to a different GCP KMS key entirely (e.g. a different project or
region), use `git vault migrate`, not `rotate` — `rotate` assumes the
resource ID is unchanged and only re-wraps under the current key's
primary version:

    git vault migrate --provider gcpkms \
      --key-resource-id projects/<other-project>/locations/global/keyRings/git-vault/cryptoKeys/git-vault-key

## Troubleshooting

- `PermissionDenied` / `403` — your account isn't granted
  `roles/cloudkms.cryptoKeyEncrypterDecrypter` on the key. Ask whoever ran
  the admin bootstrap step to add you (or your group).
- `no valid resource ID found in "..."` — the `--key-resource-id` doesn't
  match `projects/P/locations/L/keyRings/R/cryptoKeys/K`. Copy it exactly
  from `gcloud kms keys create`'s output or `gcloud kms keys list`.
- "no Google credentials found — run `gcloud auth application-default
  login` first" — exactly that: ADC hasn't been set up on this machine
  yet.
```

- [ ] **Step 2: Update `README.md`**

Replace the Status paragraph:

```markdown
**Status:** early — encrypt/decrypt, the clean/smudge filter, and status
reporting work today using a local per-machine key. Team key-sharing
providers (SSO, etc.) are on the roadmap; `git vault login` isn't
implemented yet.
```

with:

```markdown
**Status:** early — encrypt/decrypt, the clean/smudge filter, status
reporting, key rotation, and cross-provider migration all work today.
GCP KMS is available as a first team key-sharing provider, authorized
through your org's existing Google Workspace SSO — see
[docs/gcpkms-provider.md](docs/gcpkms-provider.md). Other cloud
providers (AWS, Azure) are on the roadmap.
```

Add a new section after "## Configure git-vault in a project"'s closing `git vault status` example, before "## Development":

```markdown
## Team key-sharing with GCP KMS

For a shared key backed by your org's existing SSO (rather than a local
per-machine key or an out-of-band passphrase), see
[docs/gcpkms-provider.md](docs/gcpkms-provider.md).
```

- [ ] **Step 3: Verify the doc against real command behavior**

Run each of these by hand in a scratch repo (a real GCP project and key are needed for this manual check — this is the one point in the whole plan that isn't exercised by the fake-KMS test suite):

```bash
git vault install --provider gcpkms --key-resource-id <a real resource ID>
git vault login
git vault rotate
git vault migrate --provider gcpkms --key-resource-id <a different real resource ID>
```

Expected: each command's actual output matches what the doc says it does. Fix any mismatch in the doc, not the code (the code is already tested in Tasks 1-7).

- [ ] **Step 4: Commit**

```bash
git add docs/gcpkms-provider.md README.md
git commit -m "docs: add GCP KMS provider setup guide, link from README"
```
