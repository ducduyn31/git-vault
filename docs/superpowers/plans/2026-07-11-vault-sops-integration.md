# Vault sops Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the stubbed `internal/vault.Seal`/`Open` with real sops-as-a-library encryption/decryption, dispatched in-process through git-vault's own keyservice, and validated end-to-end by a new real `local` age-based key provider.

**Architecture:** `Vault` wraps `*keyservice.Server` in-process via `sopskeyservice.NewCustomLocalClient` (no gRPC listener). `Seal`/`Open` (file-path) and `SealStream`/`OpenStream` (io.Reader/io.Writer, for later clean/smudge wiring) pick a sops `Store` by file extension (YAML/JSON structure-preserving, `.env`/`.env.*` dotenv, everything else binary), build/load a `sops.Tree`, and drive `Tree.Encrypt`/`Decrypt` + `Metadata.UpdateMasterKeysWithKeyServices`/`GetDataKeyWithKeyServices` directly from the base `github.com/getsops/sops/v3` package. A new `internal/keyservice/local` package provides the first real, working `Provider`: a locally generated X25519 age identity (via `filippo.io/age`) that a solo/single-machine repo can use today, and that this plan's own tests use as their integration fixture.

**Tech Stack:** Go 1.26, `github.com/getsops/sops/v3` (already a dependency), `filippo.io/age` (already an indirect dependency of sops — this plan makes it direct), `github.com/stretchr/testify` for assertions (existing convention in this repo).

## Global Constraints

- Go 1.26.4 floor (go.mod `go 1.26.4`).
- `golangci-lint run` must pass: standard linter set (errcheck, govet, ineffassign, staticcheck, unused) plus `gofumpt` formatting (`.golangci.yml`).
- Use `github.com/stretchr/testify/require` for test assertions, matching every existing `_test.go` file in this repo.
- Do **not** import `github.com/getsops/sops/v3/cmd/sops/common` or `.../cmd/sops/formats`. That package directly imports `github.com/urfave/cli`, a dependency this plan otherwise avoids. Everything actually needed (`Tree.Encrypt`/`Decrypt`, `Metadata.UpdateMasterKeysWithKeyServices`/`GetDataKeyWithKeyServices`, the per-format `Store` constructors) is public on the base `sops`, `sops/aes`, `sops/age`, and `sops/stores/{yaml,json,dotenv}` packages. Task 3 inlines the ~10 lines of MAC-check logic `cmd/sops/common.DecryptTree` would otherwise have provided, so no security property is lost.
- **Known, accepted dependency footprint:** using sops-as-a-library at all (the base `sops` package, needed for `sops.Tree`/`Metadata`) unavoidably pulls in `github.com/lib/pq`, `github.com/pkg/errors`, `github.com/goware/prefixer`, and `github.com/mitchellh/go-wordwrap` via `sops`'s own `audit.go`/`usererrors.go` — regardless of whether `cmd/sops/common` is used. Separately, `sops/stores/{yaml,json,dotenv}` each import `sops/config` (the `.sops.yaml` creation-rules parser), which pulls in every native sops key backend (KMS, GCP KMS, Azure Key Vault, HashiCorp Vault, PGP — already present in `go.mod` since Task 0's scaffold imported `sops/keyservice`) **plus** `sops/publish`, which is genuinely new: `cloud.google.com/go/storage` and two `aws-sdk-go-v2` S3 packages, for a cloud-upload feature this project never calls. This was verified directly (`go mod tidy` was run against a throwaway copy of this plan's own code, real Seal/Open round-trips passed). There is no way to use sops's built-in YAML/JSON/dotenv `Store` implementations without this cost — reimplementing them to dodge it would be a far worse violation of "don't re-implement the library." Accept it; it does not reopen the structured-vs-binary format decision (binary pulls the identical `sops/config` cost, since `stores/json`'s `BinaryStore` lives in the same file/package as its structured `Store`).
- **Encrypted values must be armored, not raw age binary.** `age.Encrypt`/`age.Decrypt` (from `filippo.io/age`) operate on raw binary ciphertext by default. sops's own `age.MasterKey.Encrypt`/`Decrypt` always wrap the writer/reader in `filippo.io/age/armor.NewWriter`/`NewReader` before calling `age.Encrypt`/`age.Decrypt`, because `EncryptedKey`/`enc` is stored as a string inside a YAML/JSON document, and raw binary bytes are not valid UTF-8 — JSON in particular silently replaces invalid bytes with U+FFFD, corrupting the ciphertext beyond recovery. This was caught empirically during the same pre-flight validation (JSON/binary round trips failed with "0 successful groups" until armoring was added; YAML happened to survive by luck because its encoder falls back to a lossless `!!binary` base64 tag for non-UTF8 strings). Task 1's `local.Provider.Encrypt`/`Decrypt` must armor/dearmor accordingly — this is already reflected in Task 1's code below.
- This plan does **not** wire any CLI command (`encrypt`, `decrypt`, `clean`, `smudge`, `install`, `login`) to the new `Vault`/`local` types — that is explicitly out of scope (see the design spec's Non-goals) and left to a follow-up plan.

---

### Task 1: `local` key provider

**Files:**
- Create: `internal/keyservice/local/local.go`
- Test: `internal/keyservice/local/local_test.go`

**Interfaces:**
- Consumes: `github.com/ducduyn31/git-vault/internal/keyservice.Provider` (interface: `Name() string`, `Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error)`, `Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error)`, defined in `internal/keyservice/provider.go`).
- Produces (for Task 3's tests):
  - `type Provider struct { IdentityPath string }`
  - `func New() (*Provider, error)` — `Provider` with `IdentityPath` set to `DefaultIdentityPath()`.
  - `func DefaultIdentityPath() (string, error)` — `<UserCacheDir>/git-vault/local/identity.txt`.
  - `func (p *Provider) Name() string` — returns `"local"`.
  - `func (p *Provider) Recipient() (string, error)` — this provider's bech32 age public key, generating and persisting a new identity at `p.IdentityPath` on first use.
  - `func (p *Provider) Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error)`
  - `func (p *Provider) Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error)`

- [ ] **Step 1: Write the failing test**

Create `internal/keyservice/local/local_test.go`:

```go
package local

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProvider_Name(t *testing.T) {
	p := &Provider{}

	require.Equal(t, "local", p.Name())
}

func TestProvider_RecipientGeneratesAndPersistsIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.txt")
	p := &Provider{IdentityPath: path}

	recipient1, err := p.Recipient()
	require.NoError(t, err)
	require.NotEmpty(t, recipient1)

	// A second Provider pointed at the same file reuses the persisted
	// identity instead of generating a new one.
	p2 := &Provider{IdentityPath: path}
	recipient2, err := p2.Recipient()
	require.NoError(t, err)
	require.Equal(t, recipient1, recipient2)
}

func TestProvider_EncryptDecryptRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.txt")
	p := &Provider{IdentityPath: path}
	recipient, err := p.Recipient()
	require.NoError(t, err)

	plaintext := []byte("a fake 32-byte sops data key!!!")

	ciphertext, err := p.Encrypt(context.Background(), recipient, plaintext)
	require.NoError(t, err)
	require.NotContains(t, string(ciphertext), string(plaintext))

	got, err := p.Decrypt(context.Background(), recipient, ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)
}

func TestProvider_Decrypt_WrongIdentityFails(t *testing.T) {
	pathA := filepath.Join(t.TempDir(), "identity.txt")
	a := &Provider{IdentityPath: pathA}
	recipientA, err := a.Recipient()
	require.NoError(t, err)

	pathB := filepath.Join(t.TempDir(), "identity.txt")
	b := &Provider{IdentityPath: pathB}
	_, err = b.Recipient()
	require.NoError(t, err)

	ciphertext, err := a.Encrypt(context.Background(), recipientA, []byte("secret"))
	require.NoError(t, err)

	_, err = b.Decrypt(context.Background(), recipientA, ciphertext)
	require.Error(t, err)
}

func TestDefaultIdentityPath(t *testing.T) {
	path, err := DefaultIdentityPath()
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(path, filepath.Join("git-vault", "local", "identity.txt")))
}

func TestNew_UsesDefaultIdentityPath(t *testing.T) {
	p, err := New()
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(p.IdentityPath, filepath.Join("git-vault", "local", "identity.txt")))
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/keyservice/local/... -v`
Expected: FAIL to compile — `undefined: Provider`, `undefined: DefaultIdentityPath`, `undefined: New`.

- [ ] **Step 3: Write the implementation**

Create `internal/keyservice/local/local.go`:

```go
// Package local implements git-vault's first real key Provider: a
// single-machine key backed by a locally generated age identity. It is
// not a team key-sharing solution — the private key never leaves the
// machine it was generated on. It doubles as internal/vault's own
// integration-test fixture, proving the sops <-> keyservice <-> Provider
// pipeline end-to-end without needing a real SSO provider built first.
package local

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// Name is the provider name used in "local:<recipient>" key identifiers
// (see internal/keyservice.Server).
const Name = "local"

// Provider is a Provider backed by a locally generated X25519 age
// identity persisted at IdentityPath.
type Provider struct {
	IdentityPath string
}

// New returns a Provider using the default identity path (see
// DefaultIdentityPath). The identity itself is not generated until
// Recipient, Encrypt, or Decrypt is first called.
func New() (*Provider, error) {
	path, err := DefaultIdentityPath()
	if err != nil {
		return nil, err
	}
	return &Provider{IdentityPath: path}, nil
}

// DefaultIdentityPath returns ~/.cache/git-vault/local/identity.txt
// (honoring $XDG_CACHE_HOME on Linux via os.UserCacheDir).
func DefaultIdentityPath() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "git-vault", "local", "identity.txt"), nil
}

// Name identifies this provider in a "local:<key-id>" identifier.
func (p *Provider) Name() string { return Name }

// Recipient returns this provider's current recipient key-id — a bech32
// age public key — generating and persisting a new identity on first
// use.
func (p *Provider) Recipient() (string, error) {
	id, err := p.identity()
	if err != nil {
		return "", err
	}
	return id.Recipient().String(), nil
}

// Encrypt encrypts plaintext (a sops data key) to the recipient named by
// keyID using real age encryption, armored (see armor.NewWriter below) so
// the result is safe to store as a string inside a YAML/JSON document —
// raw binary age output is not valid UTF-8 and JSON in particular would
// silently corrupt it.
func (p *Provider) Encrypt(_ context.Context, keyID string, plaintext []byte) ([]byte, error) {
	recipient, err := age.ParseX25519Recipient(keyID)
	if err != nil {
		return nil, fmt.Errorf("local: parse recipient %q: %w", keyID, err)
	}

	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, recipient)
	if err != nil {
		return nil, fmt.Errorf("local: encrypt: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("local: encrypt: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("local: encrypt: %w", err)
	}
	if err := aw.Close(); err != nil {
		return nil, fmt.Errorf("local: encrypt: close armor: %w", err)
	}
	return buf.Bytes(), nil
}

// Decrypt decrypts armored ciphertext (see Encrypt) using this provider's
// persisted identity. keyID is not consulted — a Provider only ever holds
// one identity.
func (p *Provider) Decrypt(_ context.Context, _ string, ciphertext []byte) ([]byte, error) {
	id, err := p.identity()
	if err != nil {
		return nil, err
	}

	ar := armor.NewReader(bytes.NewReader(ciphertext))
	r, err := age.Decrypt(ar, id)
	if err != nil {
		return nil, fmt.Errorf("local: decrypt: %w", err)
	}
	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("local: decrypt: %w", err)
	}
	return plaintext, nil
}

// identity loads the identity persisted at p.IdentityPath, generating and
// persisting a new one if none exists yet.
func (p *Provider) identity() (*age.X25519Identity, error) {
	data, err := os.ReadFile(p.IdentityPath)
	if err == nil {
		id, err := age.ParseX25519Identity(strings.TrimSpace(string(data)))
		if err != nil {
			return nil, fmt.Errorf("local: parse identity: %w", err)
		}
		return id, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("local: read identity: %w", err)
	}

	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("local: generate identity: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(p.IdentityPath), 0o700); err != nil {
		return nil, fmt.Errorf("local: create identity dir: %w", err)
	}
	if err := os.WriteFile(p.IdentityPath, []byte(id.String()+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("local: write identity: %w", err)
	}
	return id, nil
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/keyservice/local/... -v`
Expected: PASS (all 6 tests).

- [ ] **Step 5: `go mod tidy` to promote `filippo.io/age` to a direct dependency**

Run: `go mod tidy`
Expected: `go.mod`'s `require` block for `filippo.io/age v1.3.1` moves from the indirect block to the direct `require (...)` block alongside `github.com/getsops/sops/v3`. No new modules are added (it was already an indirect dependency of sops).

- [ ] **Step 6: Verify build and lint**

Run: `go build ./... && golangci-lint run ./internal/keyservice/...`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add internal/keyservice/local go.mod go.sum
git commit -m "feat: add local age-based key provider"
```

---

### Task 2: `Format` detection in `internal/vault`

**Files:**
- Create: `internal/vault/format.go`
- Test: `internal/vault/format_test.go`

**Interfaces:**
- Produces (for Task 3):
  - `type Format int` with constants `FormatBinary`, `FormatDotenv`, `FormatJSON`, `FormatYAML`.
  - `func FormatForPath(path string) Format`
  - `func storeForFormat(format Format) sops.Store` (unexported; Task 3 calls it directly since it lives in the same package).

- [ ] **Step 1: Write the failing test**

Create `internal/vault/format_test.go`:

```go
package vault

import "testing"

func TestFormatForPath(t *testing.T) {
	cases := []struct {
		path string
		want Format
	}{
		{"secret.yaml", FormatYAML},
		{"secret.yml", FormatYAML},
		{"config/secret.json", FormatJSON},
		{".env", FormatDotenv},
		{".env.production", FormatDotenv},
		{"config/.env.local", FormatDotenv},
		{"app.env", FormatDotenv},
		{"key.pem", FormatBinary},
		{"noextension", FormatBinary},
		{"backup.env.old/config.yaml", FormatYAML},
		{"config.env.json", FormatJSON},
		{"secrets.env.yaml", FormatYAML},
	}

	for _, c := range cases {
		if got := FormatForPath(c.path); got != c.want {
			t.Errorf("FormatForPath(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestStoreForFormat_ReturnsNonNilForEveryFormat(t *testing.T) {
	for _, f := range []Format{FormatBinary, FormatDotenv, FormatJSON, FormatYAML} {
		if storeForFormat(f) == nil {
			t.Errorf("storeForFormat(%v) = nil", f)
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/vault/... -v -run 'TestFormatForPath|TestStoreForFormat'`
Expected: FAIL to compile — `undefined: Format`, `undefined: FormatForPath`, etc.

- [ ] **Step 3: Write the implementation**

Create `internal/vault/format.go`:

```go
package vault

import (
	"path/filepath"
	"strings"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/stores/dotenv"
	"github.com/getsops/sops/v3/stores/json"
	"github.com/getsops/sops/v3/stores/yaml"
)

// Format identifies which sops store git-vault uses for a document.
type Format int

const (
	// FormatBinary treats the whole file as one opaque ciphertext blob.
	// It is the fallback for any extension not otherwise recognized.
	FormatBinary Format = iota
	// FormatDotenv preserves KEY=value structure; only values are
	// encrypted.
	FormatDotenv
	// FormatJSON preserves object structure; only leaf values are
	// encrypted.
	FormatJSON
	// FormatYAML preserves document structure; only leaf values are
	// encrypted.
	FormatYAML
)

// FormatForPath returns the Format git-vault uses for path, based on its
// file extension: .yaml/.yml and .json get sops's structure-preserving
// stores; ".env" and any ".env.<suffix>" file (e.g. ".env.production")
// get the dotenv store; anything else falls back to the binary
// (whole-file) store.
func FormatForPath(path string) Format {
	base := filepath.Base(path)
	switch {
	case strings.HasSuffix(base, ".json"):
		return FormatJSON
	case strings.HasSuffix(base, ".yaml"), strings.HasSuffix(base, ".yml"):
		return FormatYAML
	case strings.HasSuffix(base, ".env") || strings.Contains(base, ".env."):
		return FormatDotenv
	default:
		return FormatBinary
	}
}

// storeForFormat returns the sops Store implementation for format. JSON
// gets an explicit 2-space indent so committed files diff cleanly
// (sops's JSON store defaults to a bare, near-compact reindent otherwise).
func storeForFormat(format Format) sops.Store {
	switch format {
	case FormatDotenv:
		return dotenv.NewStore(&config.DotenvStoreConfig{})
	case FormatJSON:
		return json.NewStore(&config.JSONStoreConfig{Indent: 2})
	case FormatYAML:
		return yaml.NewStore(&config.YAMLStoreConfig{})
	default:
		return json.NewBinaryStore(&config.JSONBinaryStoreConfig{})
	}
}
```

- [ ] **Step 4: `go mod tidy`**

Run: `go mod tidy`
Expected: this downloads and adds a real chunk of new indirect dependencies — `cloud.google.com/go/storage`, two `aws-sdk-go-v2` S3 packages, and their own transitive trees (opentelemetry exporters, etc.), plus `github.com/lib/pq`, `github.com/pkg/errors`, `github.com/goware/prefixer`, `github.com/mitchellh/go-wordwrap`. This is expected — see the "Known, accepted dependency footprint" global constraint above — and is not a sign anything is wrong. `go.sum` will grow substantially; that is correct.

- [ ] **Step 5: Run the test to verify it passes**

Run: `go test ./internal/vault/... -v -run 'TestFormatForPath|TestStoreForFormat'`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/vault/format.go internal/vault/format_test.go go.mod go.sum
git commit -m "feat: add sops format detection to internal/vault"
```

---

### Task 3: Real `Seal`/`Open`/`SealStream`/`OpenStream`

**Files:**
- Modify: `internal/vault/vault.go` (replace entirely — current stub content is being removed)
- Modify: `internal/vault/vault_test.go` (replace entirely — current stub tests are being removed)

**Interfaces:**
- Consumes:
  - `internal/keyservice.Server` (`func NewServer(registry *Registry) *Server`, from `internal/keyservice/server.go`, already implemented).
  - `internal/keyservice.Registry` (`func NewRegistry() *Registry`, `func (r *Registry) Register(p Provider) error`, from `internal/keyservice/registry.go`, already implemented).
  - `local.Provider` (Task 1): `&local.Provider{IdentityPath: path}`, `(*local.Provider).Recipient() (string, error)`.
  - `Format`, `FormatForPath`, `storeForFormat` (Task 2, same package).
- Produces:
  - `func New(server *keyservice.Server) *Vault`
  - `func (v *Vault) Seal(path string, recipients []string) error`
  - `func (v *Vault) Open(path string) error`
  - `func (v *Vault) SealStream(w io.Writer, r io.Reader, format Format, recipients []string) error`
  - `func (v *Vault) OpenStream(w io.Writer, r io.Reader, format Format) error`

- [ ] **Step 1: Write the failing test**

Replace `internal/vault/vault_test.go` entirely:

```go
package vault

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	yamlv3 "gopkg.in/yaml.v3"

	"github.com/ducduyn31/git-vault/internal/keyservice"
	"github.com/ducduyn31/git-vault/internal/keyservice/local"
)

func newTestVault(t *testing.T) (*Vault, []string) {
	t.Helper()

	provider := &local.Provider{IdentityPath: filepath.Join(t.TempDir(), "identity.txt")}
	recipient, err := provider.Recipient()
	require.NoError(t, err)

	registry := keyservice.NewRegistry()
	require.NoError(t, registry.Register(provider))
	server := keyservice.NewServer(registry)

	return New(server), []string{"local:" + recipient}
}

func TestSealOpen_YAMLRoundTrip(t *testing.T) {
	v, recipients := newTestVault(t)
	path := filepath.Join(t.TempDir(), "secret.yaml")
	original := "database:\n  password: hunter2\n  username: admin\n"
	require.NoError(t, os.WriteFile(path, []byte(original), 0o644))

	require.NoError(t, v.Seal(path, recipients))

	sealed, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NotContains(t, string(sealed), "hunter2")
	require.Contains(t, string(sealed), "password: ENC[")
	require.Contains(t, string(sealed), "username: ENC[")

	require.NoError(t, v.Open(path))

	opened, err := os.ReadFile(path)
	require.NoError(t, err)

	var originalMap, roundTrippedMap map[string]interface{}
	require.NoError(t, yamlv3.Unmarshal([]byte(original), &originalMap))
	require.NoError(t, yamlv3.Unmarshal(opened, &roundTrippedMap))
	require.Equal(t, originalMap, roundTrippedMap)
}

func TestSealOpen_JSONRoundTrip(t *testing.T) {
	v, recipients := newTestVault(t)
	path := filepath.Join(t.TempDir(), "secret.json")
	original := `{"password":"hunter2","username":"admin"}`
	require.NoError(t, os.WriteFile(path, []byte(original), 0o644))

	require.NoError(t, v.Seal(path, recipients))

	sealed, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NotContains(t, string(sealed), "hunter2")

	require.NoError(t, v.Open(path))

	opened, err := os.ReadFile(path)
	require.NoError(t, err)

	var originalMap, roundTrippedMap map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(original), &originalMap))
	require.NoError(t, json.Unmarshal(opened, &roundTrippedMap))
	require.Equal(t, originalMap, roundTrippedMap)
}

func TestSealOpen_DotenvRoundTrip(t *testing.T) {
	v, recipients := newTestVault(t)
	path := filepath.Join(t.TempDir(), ".env.production")
	original := "API_KEY=supersecret\nDEBUG=true\n"
	require.NoError(t, os.WriteFile(path, []byte(original), 0o644))

	require.NoError(t, v.Seal(path, recipients))

	sealed, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NotContains(t, string(sealed), "supersecret")
	require.Contains(t, string(sealed), "API_KEY=ENC[")

	require.NoError(t, v.Open(path))

	opened, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, original, string(opened))
}

func TestSealOpen_BinaryRoundTrip(t *testing.T) {
	v, recipients := newTestVault(t)
	path := filepath.Join(t.TempDir(), "key.pem")
	original := []byte("-----BEGIN PRIVATE KEY-----\nnotarealkey\n-----END PRIVATE KEY-----\n")
	require.NoError(t, os.WriteFile(path, original, 0o644))

	require.NoError(t, v.Seal(path, recipients))

	sealed, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NotContains(t, string(sealed), "notarealkey")

	require.NoError(t, v.Open(path))

	opened, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, original, opened)
}

func TestSeal_NoRecipientsErrors(t *testing.T) {
	v, _ := newTestVault(t)
	path := filepath.Join(t.TempDir(), "secret.yaml")
	require.NoError(t, os.WriteFile(path, []byte("a: b\n"), 0o644))

	require.Error(t, v.Seal(path, nil))
}

func TestOpen_TamperedMacFails(t *testing.T) {
	v, recipients := newTestVault(t)
	path := filepath.Join(t.TempDir(), "secret.env")
	require.NoError(t, os.WriteFile(path, []byte("A=b\n"), 0o644))
	require.NoError(t, v.Seal(path, recipients))

	sealed, err := os.ReadFile(path)
	require.NoError(t, err)
	tampered := string(sealed) + "INJECTED=x\n"
	require.NoError(t, os.WriteFile(path, []byte(tampered), 0o644))

	require.Error(t, v.Open(path))
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/vault/... -v`
Expected: FAIL to compile — `New` still takes a `string` (`KeyserviceAddr`), not `*keyservice.Server`; `Seal`/`Open` don't take a `recipients`/exist with the old signature.

- [ ] **Step 3: Write the implementation**

Replace `internal/vault/vault.go` entirely:

```go
// Package vault wraps sops-as-a-library, configured to route key
// operations through git-vault's local keyservice (internal/keyservice),
// in-process — no network listener is involved. See
// docs/superpowers/specs/2026-07-11-vault-sops-integration-design.md.
package vault

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/aes"
	sopskeyservice "github.com/getsops/sops/v3/keyservice"

	"github.com/ducduyn31/git-vault/internal/keyservice"
)

// sopsVersion is written into new files' sops.version metadata field. It
// is a plain literal, not sops's own version.Version const, because that
// package imports github.com/urfave/cli purely for its CLI-version-check
// subcommand — a dependency this plan otherwise avoids. Keep this in sync
// with the github.com/getsops/sops/v3 version pinned in go.mod.
const sopsVersion = "3.13.2"

// Vault seals/opens files using sops, dispatching key operations to
// git-vault's own keyservice.Server in-process via
// sopskeyservice.NewCustomLocalClient.
type Vault struct {
	clients []sopskeyservice.KeyServiceClient
}

// New returns a Vault that dispatches key operations to server in-process.
func New(server *keyservice.Server) *Vault {
	return &Vault{
		clients: []sopskeyservice.KeyServiceClient{sopskeyservice.NewCustomLocalClient(server)},
	}
}

// Seal encrypts the file at path in place, creating a fresh sops tree
// keyed to recipients (opaque "<provider>:<key-id>" identifiers — see
// internal/keyservice.Server).
func (v *Vault) Seal(path string, recipients []string) error {
	plaintext, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("vault: read %s: %w", path, err)
	}

	var out bytes.Buffer
	if err := v.SealStream(&out, bytes.NewReader(plaintext), FormatForPath(path), recipients); err != nil {
		return err
	}
	return os.WriteFile(path, out.Bytes(), 0o644)
}

// Open decrypts the file at path in place.
func (v *Vault) Open(path string) error {
	ciphertext, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("vault: read %s: %w", path, err)
	}

	var out bytes.Buffer
	if err := v.OpenStream(&out, bytes.NewReader(ciphertext), FormatForPath(path)); err != nil {
		return err
	}
	return os.WriteFile(path, out.Bytes(), 0o644)
}

// SealStream encrypts r (formatted per format), writing the sealed result
// to w. Used later by git's clean filter, which gets file content on
// stdin/stdout rather than a real path.
func (v *Vault) SealStream(w io.Writer, r io.Reader, format Format, recipients []string) error {
	if len(recipients) == 0 {
		return fmt.Errorf("vault: seal: no recipients provided")
	}

	plaintext, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("vault: read plaintext: %w", err)
	}

	store := storeForFormat(format)
	branches, err := store.LoadPlainFile(plaintext)
	if err != nil {
		return fmt.Errorf("vault: parse plaintext: %w", err)
	}

	keyGroup := make(sops.KeyGroup, len(recipients))
	for i, recipient := range recipients {
		keyGroup[i] = &age.MasterKey{Recipient: recipient}
	}

	tree := sops.Tree{
		Branches: branches,
		Metadata: sops.Metadata{
			KeyGroups: []sops.KeyGroup{keyGroup},
			Version:   sopsVersion,
		},
	}

	dataKey, errs := tree.GenerateDataKeyWithKeyServices(v.clients)
	if len(errs) > 0 {
		return fmt.Errorf("vault: generate data key: %w", errors.Join(errs...))
	}

	cipher := aes.NewCipher()
	unencryptedMac, err := tree.Encrypt(dataKey, cipher)
	if err != nil {
		return fmt.Errorf("vault: encrypt: %w", err)
	}
	tree.Metadata.LastModified = time.Now().UTC()
	mac, err := cipher.Encrypt(unencryptedMac, dataKey, tree.Metadata.LastModified.Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("vault: encrypt mac: %w", err)
	}
	tree.Metadata.MessageAuthenticationCode = mac

	out, err := store.EmitEncryptedFile(tree)
	if err != nil {
		return fmt.Errorf("vault: emit encrypted file: %w", err)
	}
	if _, err := w.Write(out); err != nil {
		return fmt.Errorf("vault: write ciphertext: %w", err)
	}
	return nil
}

// OpenStream decrypts r (formatted per format), writing the plaintext to
// w. Used later by git's smudge filter.
func (v *Vault) OpenStream(w io.Writer, r io.Reader, format Format) error {
	ciphertext, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("vault: read ciphertext: %w", err)
	}

	store := storeForFormat(format)
	tree, err := store.LoadEncryptedFile(ciphertext)
	if err != nil {
		return fmt.Errorf("vault: parse ciphertext: %w", err)
	}

	dataKey, err := tree.Metadata.GetDataKeyWithKeyServices(v.clients, nil)
	if err != nil {
		return fmt.Errorf("vault: get data key: %w", err)
	}

	cipher := aes.NewCipher()
	computedMac, err := tree.Decrypt(dataKey, cipher)
	if err != nil {
		return fmt.Errorf("vault: decrypt: %w", err)
	}
	fileMac, err := cipher.Decrypt(tree.Metadata.MessageAuthenticationCode, dataKey, tree.Metadata.LastModified.Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("vault: decrypt mac: %w", err)
	}
	if fileMac != computedMac {
		return fmt.Errorf("vault: mac mismatch, file may have been tampered with")
	}

	out, err := store.EmitPlainFile(tree.Branches)
	if err != nil {
		return fmt.Errorf("vault: emit plain file: %w", err)
	}
	if _, err := w.Write(out); err != nil {
		return fmt.Errorf("vault: write plaintext: %w", err)
	}
	return nil
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/vault/... -v`
Expected: PASS (all 7 tests: YAML/JSON/dotenv/binary round trips, no-recipients error, tampered-MAC error).

- [ ] **Step 5: Run the full test suite**

Run: `go test ./...`
Expected: PASS across every package (`internal/cli`, `internal/config`, `internal/gitattr`, `internal/keyservice`, `internal/keyservice/local`, `internal/session`, `internal/vault`).

- [ ] **Step 6: Verify build and lint**

Run: `go build ./... && golangci-lint run`
Expected: no errors. If `gofumpt` reports formatting issues, run `gofumpt -l -w .` and re-run.

- [ ] **Step 7: Commit**

```bash
git add internal/vault/vault.go internal/vault/vault_test.go
git commit -m "feat: implement real sops Seal/Open in internal/vault"
```

---

### Task 4: Final integration check

**Files:** none (verification only).

- [ ] **Step 1: Run the project's own task runner end to end**

Run: `task test && task lint && task build`
Expected: all three succeed; `git-vault` binary is produced in the repo root.

- [ ] **Step 2: Clean up the built binary**

Run: `rm -f git-vault`

(The binary is a build artifact, not committed — confirm via `git status` that it does not appear as untracked before/after.)

- [ ] **Step 3: Confirm no unintended changes**

Run: `git status --short`
Expected: clean working tree (everything from Tasks 1-3 already committed); no leftover `git-vault` binary or stray files.
