# Passphrase/local Provider Rotation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make passphrase entry interactive (TTY prompt, env var stays as a CI fallback) and give both `local` and `passphrase` providers an ordered multi-key model, so a new `git vault rotate` command can rotate a provider's key in place — something `migrate` today explicitly refuses to do.

**Architecture:** Both providers move from "exactly one key" to "an ordered list of keys, newest last": `Encrypt` always targets the newest, `Decrypt` accepts whichever key actually produced the ciphertext. `local` persists its list in a renamed, multi-line identity file (`identities`, reusing `age.ParseIdentities`' native one-per-line format); `passphrase` reads its list from a newline-separated `GIT_VAULT_PASSPHRASE`. A new `internal/cli/rotate.go` generates fresh key material per-provider and re-seals every tracked file, mirroring `migrate.go`'s existing reseal loop.

**Tech Stack:** Go 1.26.4, `filippo.io/age` v1.3.1 (already a direct dependency), `golang.org/x/term` v0.44.0 (currently indirect — this plan promotes it to direct via `go mod tidy`), `github.com/spf13/cobra`, `github.com/stretchr/testify/require`.

## Global Constraints

- No new third-party dependencies beyond promoting `golang.org/x/term` (already resolved in `go.sum` at v0.44.0) from indirect to direct.
- `keyservice.Provider`'s interface (`Name`/`Encrypt`/`Decrypt` in `internal/keyservice/provider.go`) does not change.
- `migrate.go` and `migrate_test.go` are not touched by this plan — same-provider rejection there is intentionally unchanged; `rotate` is the new, separate command for that case.
- Every new error is wrapped with a `"<package>: "` or `"git vault rotate: "` prefix, matching this codebase's existing convention (see `passphrase.go`, `local.go`, `migrate.go`).
- All new/changed exported identifiers get a doc comment, matching every existing exported identifier in this codebase.

---

### Task 1: `passphrase` provider — multi-passphrase + interactive prompt

**Files:**
- Modify: `internal/keyservice/passphrase/passphrase.go`
- Modify: `internal/keyservice/passphrase/passphrase_test.go`
- Modify: `go.mod`, `go.sum` (via `go get`/`go mod tidy`)

**Interfaces:**
- Consumes: `filippo.io/age` (`NewScryptRecipient`, `NewScryptIdentity`, `Decrypt`, `Encrypt`, `Identity`), `filippo.io/age/armor`, `golang.org/x/term` (`IsTerminal`, `ReadPassword`).
- Produces (for Task 3): `passphrase.New() *Provider` (changed return type from value to pointer — call sites using it as an interface value are unaffected), `passphrase.NewWithSecret(secret string) *Provider`, `passphrase.PromptNewSecret(out io.Writer) (string, error)`, `passphrase.SetPromptForTesting(fn func() (string, error)) (restore func())`.

Today `passphrase.go` reads a single passphrase from `GIT_VAULT_PASSPHRASE` fresh on every `Encrypt`/`Decrypt` call, via a stateless value-type `Provider{}`. This task changes the env var format to newline-separated (oldest first, newest last — a single line keeps working exactly as before), adds a terminal prompt fallback when the env var is unset, and adds two new constructors `rotate` (Task 3) will need.

**Verified before writing this task:** `age.Decrypt(src, identities...)` accepts multiple `*ScryptIdentity` values in one call with no "must be the only one" restriction — that restriction (`scrypt.go`: `"an scrypt recipient must be the only one"`) applies only to `ScryptRecipient` on the *encrypt* side. Confirmed by running a small standalone program against `filippo.io/age@v1.3.1`: encrypting with one scrypt recipient, then calling `age.Decrypt(ciphertext, wrongIdentity, correctIdentity)` — it succeeds, trying each in turn.

- [ ] **Step 1: Write failing test for multi-line passphrase decrypt + newest-line encrypt**

Add to `internal/keyservice/passphrase/passphrase_test.go`:

```go
func TestProvider_Decrypt_OlderLineStillDecrypts(t *testing.T) {
	t.Setenv(EnvVar, "old passphrase")
	p := New()
	ciphertext, err := p.Encrypt(context.Background(), KeyID, []byte("secret"))
	require.NoError(t, err)

	// Rotate: the env var now carries both lines, newest last. A file
	// still sealed under the older line must still open.
	t.Setenv(EnvVar, "old passphrase\nnew passphrase")
	p2 := New()
	got, err := p2.Decrypt(context.Background(), KeyID, ciphertext)
	require.NoError(t, err)
	require.Equal(t, []byte("secret"), got)
}

func TestProvider_Encrypt_UsesNewestLine(t *testing.T) {
	t.Setenv(EnvVar, "old passphrase\nnew passphrase")
	p := New()
	ciphertext, err := p.Encrypt(context.Background(), KeyID, []byte("secret"))
	require.NoError(t, err)

	// Only the newest line can open it.
	t.Setenv(EnvVar, "new passphrase")
	p2 := New()
	got, err := p2.Decrypt(context.Background(), KeyID, ciphertext)
	require.NoError(t, err)
	require.Equal(t, []byte("secret"), got)

	t.Setenv(EnvVar, "old passphrase")
	p3 := New()
	_, err = p3.Decrypt(context.Background(), KeyID, ciphertext)
	require.Error(t, err)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/keyservice/passphrase/... -run 'TestProvider_Decrypt_OlderLineStillDecrypts|TestProvider_Encrypt_UsesNewestLine' -v`
Expected: FAIL — today's `lookupPassphrase` treats the whole multi-line env var as one literal passphrase string, so `TestProvider_Decrypt_OlderLineStillDecrypts`'s second `Decrypt` call fails (the literal string `"old passphrase\nnew passphrase"` isn't the passphrase `"old passphrase"` the file was sealed with).

- [ ] **Step 3: Rewrite `passphrase.go`**

Replace the full contents of `internal/keyservice/passphrase/passphrase.go`:

```go
// Package passphrase implements a keyservice.Provider backed by a shared
// secret read from an environment variable, encrypted with age's scrypt
// (password-based) recipient. Unlike internal/keyservice/local, the same
// passphrase can be distributed to a team out-of-band (e.g. a secrets
// manager or password vault) — there is no per-machine identity and no
// login flow, at the cost of weaker rotation and audit than a real
// SSO/KMS-backed provider.
//
// GIT_VAULT_PASSPHRASE holds one or more passphrases, one per line, oldest
// first and the current one last — a single-line value keeps working
// exactly as before. Encrypt always targets the newest line; Decrypt
// tries every line, so a file sealed under an older passphrase keeps
// opening for as long as that line is still present, e.g. during a
// `rotate` transition (see internal/cli/rotate.go).
package passphrase

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
	"golang.org/x/term"
)

// Name is the provider name used in "passphrase:<key-id>" key identifiers
// (see internal/keyservice.Server).
const Name = "passphrase"

// EnvVar is the environment variable this provider reads its passphrase(s)
// from, newline-separated, oldest first.
const EnvVar = "GIT_VAULT_PASSPHRASE"

// KeyID is the fixed key-id this provider uses: a passphrase-backed
// recipient is never versioned by key-id, only by how many lines
// EnvVar carries — see the package doc comment.
const KeyID = "shared"

// promptFn reads one passphrase interactively. A package-level variable so
// tests can replace it without a real terminal attached to stdin; see
// SetPromptForTesting.
var promptFn = defaultPrompt

// defaultPrompt prompts on stderr and reads hidden input from the
// controlling terminal. Returns an error immediately, without blocking,
// if stdin isn't a terminal.
func defaultPrompt() (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("passphrase: %s not set and stdin is not a terminal to prompt for one", EnvVar)
	}
	if _, err := fmt.Fprint(os.Stderr, "git-vault passphrase: "); err != nil {
		return "", err
	}
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("passphrase: read prompt: %w", err)
	}
	return string(b), nil
}

// SetPromptForTesting overrides the interactive prompt used by the
// env-var fallback and by PromptNewSecret. It returns a function that
// restores the previous prompt — call it via defer. For use in tests
// only, including from other packages that need to drive `rotate`
// (internal/cli) without a real terminal.
func SetPromptForTesting(fn func() (string, error)) (restore func()) {
	prev := promptFn
	promptFn = fn
	return func() { promptFn = prev }
}

// Provider is a Provider backed by the passphrase(s) in EnvVar, or by a
// single explicit secret (see NewWithSecret). It caches an interactively
// prompted secret so a command touching many tracked files only prompts
// once per process; the env var itself is re-read fresh on every call
// since that's cheap and needs no caching.
type Provider struct {
	explicit []string // set by NewWithSecret; bypasses EnvVar entirely
	prompted []string // cached result of an interactive prompt
}

// New returns a Provider reading from EnvVar (or prompting interactively
// if it's unset and stdin is a terminal).
func New() *Provider { return &Provider{} }

// NewWithSecret returns a Provider fixed to secret, bypassing EnvVar and
// any prompt entirely. Used by `rotate` (internal/cli) to build the "new"
// side of a rotation — passphrase has no local file to persist a rotated
// secret into, so the fresh secret only ever exists as this one in-memory
// value plus whatever the user does with it afterward.
func NewWithSecret(secret string) *Provider {
	return &Provider{explicit: []string{secret}}
}

// PromptNewSecret always prompts interactively (no EnvVar alternative,
// since generating a new passphrase is a deliberate one-off action, not
// routine CI traffic), entered twice to catch typos since there's no
// on-screen echo. out receives the two instructional lines; the prompt
// and hidden input themselves still go through promptFn.
func PromptNewSecret(out io.Writer) (string, error) {
	if _, err := fmt.Fprintln(out, "Enter new passphrase:"); err != nil {
		return "", err
	}
	first, err := promptFn()
	if err != nil {
		return "", err
	}
	if _, err := fmt.Fprintln(out, "Confirm new passphrase:"); err != nil {
		return "", err
	}
	second, err := promptFn()
	if err != nil {
		return "", err
	}
	if first != second {
		return "", fmt.Errorf("passphrase: entries did not match")
	}
	return first, nil
}

func (p *Provider) Name() string { return Name }

// Encrypt encrypts plaintext (a sops data key) using real age scrypt
// encryption, armored (see armor.NewWriter below) so the result is safe
// to store as a string inside a YAML/JSON document — raw binary age
// output is not valid UTF-8 and JSON in particular would silently
// corrupt it. keyID is ignored: the secret(s) in scope are the only key
// material, and Encrypt always targets the newest one.
func (p *Provider) Encrypt(_ context.Context, _ string, plaintext []byte) ([]byte, error) {
	secrets, err := p.lookup()
	if err != nil {
		return nil, err
	}
	recipient, err := age.NewScryptRecipient(secrets[len(secrets)-1])
	if err != nil {
		return nil, fmt.Errorf("passphrase: %w", err)
	}

	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, recipient)
	if err != nil {
		return nil, fmt.Errorf("passphrase: encrypt: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("passphrase: encrypt: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("passphrase: encrypt: %w", err)
	}
	if err := aw.Close(); err != nil {
		return nil, fmt.Errorf("passphrase: encrypt: close armor: %w", err)
	}
	return buf.Bytes(), nil
}

// Decrypt decrypts armored ciphertext (see Encrypt) trying every secret
// in scope, newest first (scrypt's KDF is deliberately slow, and the
// common case post-rotation is that the newest passphrase is the one in
// use). keyID is ignored, for the same reason as Encrypt.
func (p *Provider) Decrypt(_ context.Context, _ string, ciphertext []byte) ([]byte, error) {
	secrets, err := p.lookup()
	if err != nil {
		return nil, err
	}
	identities := make([]age.Identity, len(secrets))
	for i, secret := range secrets {
		id, err := age.NewScryptIdentity(secret)
		if err != nil {
			return nil, fmt.Errorf("passphrase: %w", err)
		}
		identities[len(secrets)-1-i] = id
	}

	ar := armor.NewReader(bytes.NewReader(ciphertext))
	r, err := age.Decrypt(ar, identities...)
	if err != nil {
		return nil, fmt.Errorf("passphrase: decrypt: %w", err)
	}
	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("passphrase: decrypt: %w", err)
	}
	return plaintext, nil
}

// lookup resolves the secrets in scope: explicit (NewWithSecret) first,
// else EnvVar (re-read fresh every call — cheap, no caching needed), else
// an interactive prompt (cached in p.prompted so a process touching many
// files only prompts once).
func (p *Provider) lookup() ([]string, error) {
	if p.explicit != nil {
		return p.explicit, nil
	}
	if raw := os.Getenv(EnvVar); raw != "" {
		return splitSecrets(raw)
	}
	if p.prompted != nil {
		return p.prompted, nil
	}
	secret, err := promptFn()
	if err != nil {
		return nil, err
	}
	p.prompted = []string{secret}
	return p.prompted, nil
}

// splitSecrets parses EnvVar's newline-separated format, dropping blank
// lines.
func splitSecrets(raw string) ([]string, error) {
	var secrets []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			secrets = append(secrets, line)
		}
	}
	if len(secrets) == 0 {
		return nil, fmt.Errorf("passphrase: %s not set", EnvVar)
	}
	return secrets, nil
}
```

- [ ] **Step 4: Run tests to verify Step 1's tests now pass**

Run: `go test ./internal/keyservice/passphrase/... -run 'TestProvider_Decrypt_OlderLineStillDecrypts|TestProvider_Encrypt_UsesNewestLine' -v`
Expected: PASS

- [ ] **Step 5: Run the full existing passphrase test suite**

Run: `go test ./internal/keyservice/passphrase/... -v`
Expected: `TestProvider_Name`, `TestProvider_EncryptDecryptRoundTrip`, and `TestProvider_Decrypt_WrongPassphraseFails` PASS unchanged. `TestProvider_Encrypt_MissingEnvVarFails` and `TestProvider_Decrypt_MissingEnvVarFails` may now hang or behave inconsistently depending on whether the test runner's stdin happens to be a real terminal — fix in the next step before treating this as done.

- [ ] **Step 6: Make the missing-env-var tests deterministic**

`TestProvider_Encrypt_MissingEnvVarFails` and `TestProvider_Decrypt_MissingEnvVarFails` set `EnvVar` to `""` expecting an immediate error — but `lookup()` now falls through to `promptFn()` when the env var is unset, and the real `defaultPrompt` behaves differently depending on whether the process's actual stdin is a terminal (true when a developer runs `go test` directly in an interactive shell without redirecting stdin, false under most CI/scripted invocations). Stub the prompt explicitly so these tests don't depend on how they happen to be invoked. Replace both tests in `internal/keyservice/passphrase/passphrase_test.go`:

```go
func TestProvider_Encrypt_MissingEnvVarFails(t *testing.T) {
	t.Setenv(EnvVar, "")
	restore := SetPromptForTesting(func() (string, error) {
		return "", fmt.Errorf("passphrase: %s not set and stdin is not a terminal to prompt for one", EnvVar)
	})
	defer restore()
	p := New()

	_, err := p.Encrypt(context.Background(), KeyID, []byte("secret"))
	require.ErrorContains(t, err, EnvVar)
}

func TestProvider_Decrypt_MissingEnvVarFails(t *testing.T) {
	t.Setenv(EnvVar, "")
	restore := SetPromptForTesting(func() (string, error) {
		return "", fmt.Errorf("passphrase: %s not set and stdin is not a terminal to prompt for one", EnvVar)
	})
	defer restore()
	p := New()

	_, err := p.Decrypt(context.Background(), KeyID, []byte("ciphertext"))
	require.ErrorContains(t, err, EnvVar)
}
```

Add `"fmt"` to that file's import block if not already present.

- [ ] **Step 7: Write tests for the new prompt-fallback and rotate-support exports**

Add to `internal/keyservice/passphrase/passphrase_test.go`:

```go
func TestProvider_Decrypt_PromptedWhenEnvUnset(t *testing.T) {
	t.Setenv(EnvVar, "")
	restore := SetPromptForTesting(func() (string, error) { return "typed passphrase", nil })
	defer restore()

	p := New()
	ciphertext, err := p.Encrypt(context.Background(), KeyID, []byte("secret"))
	require.NoError(t, err)

	got, err := p.Decrypt(context.Background(), KeyID, ciphertext)
	require.NoError(t, err)
	require.Equal(t, []byte("secret"), got)
}

func TestNewWithSecret_BypassesEnvVar(t *testing.T) {
	t.Setenv(EnvVar, "env passphrase")
	p := NewWithSecret("explicit passphrase")

	ciphertext, err := p.Encrypt(context.Background(), KeyID, []byte("secret"))
	require.NoError(t, err)

	// Only the explicit secret opens it, not the env var's value.
	envP := New()
	_, err = envP.Decrypt(context.Background(), KeyID, ciphertext)
	require.Error(t, err)

	got, err := p.Decrypt(context.Background(), KeyID, ciphertext)
	require.NoError(t, err)
	require.Equal(t, []byte("secret"), got)
}

func TestPromptNewSecret_MatchingEntriesSucceed(t *testing.T) {
	restore := SetPromptForTesting(func() (string, error) { return "new passphrase", nil })
	defer restore()

	got, err := PromptNewSecret(&bytes.Buffer{})
	require.NoError(t, err)
	require.Equal(t, "new passphrase", got)
}

func TestPromptNewSecret_MismatchedEntriesFail(t *testing.T) {
	calls := 0
	restore := SetPromptForTesting(func() (string, error) {
		calls++
		if calls == 1 {
			return "first entry", nil
		}
		return "second entry", nil
	})
	defer restore()

	_, err := PromptNewSecret(&bytes.Buffer{})
	require.ErrorContains(t, err, "did not match")
}
```

Add `"bytes"` to that file's import block if not already present.

- [ ] **Step 8: Run the full test suite to confirm everything passes**

Run: `go test ./internal/keyservice/passphrase/... -v`
Expected: PASS — all tests, old and new.

- [ ] **Step 9: Promote `golang.org/x/term` to a direct dependency**

Run:
```bash
go mod tidy
```
Expected: `go.mod`'s `require` block gains `golang.org/x/term v0.44.0` in the direct (non-`// indirect`) group; `go.sum` is unchanged (the module was already resolved as an indirect dependency at this exact version).

Verify: `git diff go.mod` shows `golang.org/x/term v0.44.0` moved out of the `// indirect` block into the top `require (...)` block alongside `filippo.io/age`, `github.com/spf13/cobra`, etc.

- [ ] **Step 10: Run the whole project's test suite**

Run: `go build ./... && go test ./...`
Expected: PASS, no build errors anywhere (this task doesn't touch any other package, but confirms nothing else imports `passphrase.New()` in a way the pointer-type change breaks).

- [ ] **Step 11: Commit**

```bash
git add internal/keyservice/passphrase/passphrase.go internal/keyservice/passphrase/passphrase_test.go go.mod go.sum
git commit -m "feat: multi-passphrase support + interactive prompt for passphrase provider"
```

---

### Task 2: `local` provider — multi-identity, renamed & configurable identity file

**Files:**
- Modify: `internal/keyservice/local/local.go`
- Modify: `internal/keyservice/local/local_test.go`

**Interfaces:**
- Consumes: `filippo.io/age` (`ParseIdentities`, `GenerateX25519Identity`, `X25519Identity`, `ParseX25519Recipient`), `filippo.io/age/armor`.
- Produces (for Task 3): `local.New() (*Provider, error)` (signature unchanged), `local.Provider.Rotate() (recipient string, err error)`, `local.IdentityPathEnvVar` (new const).

Today `local.go` persists exactly one age identity at a fixed path
(`identity.txt`), loaded/generated by `identity()`. This task renames the
file to `identities` (no extension — it's a list now), makes its path
configurable, changes it to hold an ordered list via `age.ParseIdentities`
(the same one-identity-per-line format the real `age` CLI already uses),
and adds `Rotate()` for Task 3.

- [ ] **Step 1: Update the two path-name assertions to the new filename**

`internal/keyservice/local/local_test.go` currently asserts the identity
file is named `identity.txt`. Update both to the new name:

```go
func TestDefaultIdentityPath(t *testing.T) {
	path, err := DefaultIdentityPath()
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(path, filepath.Join("git-vault", "local", "identities")))
}

func TestNew_UsesDefaultIdentityPath(t *testing.T) {
	p, err := New()
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(p.IdentityPath, filepath.Join("git-vault", "local", "identities")))
}
```

- [ ] **Step 2: Write failing tests for multi-identity support and `Rotate`**

Add to `internal/keyservice/local/local_test.go`:

```go
func TestProvider_Rotate_OlderIdentityStillDecrypts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identities")
	p := &Provider{IdentityPath: path}

	oldRecipient, err := p.Recipient()
	require.NoError(t, err)

	ciphertext, err := p.Encrypt(context.Background(), oldRecipient, []byte("secret"))
	require.NoError(t, err)

	newRecipient, err := p.Rotate()
	require.NoError(t, err)
	require.NotEqual(t, oldRecipient, newRecipient)

	// Recipient() now reports the newest identity.
	current, err := p.Recipient()
	require.NoError(t, err)
	require.Equal(t, newRecipient, current)

	// The file the old ciphertext names as its recipient still decrypts.
	got, err := p.Decrypt(context.Background(), oldRecipient, ciphertext)
	require.NoError(t, err)
	require.Equal(t, []byte("secret"), got)

	// New ciphertext targets the new recipient.
	newCiphertext, err := p.Encrypt(context.Background(), newRecipient, []byte("secret2"))
	require.NoError(t, err)
	got2, err := p.Decrypt(context.Background(), newRecipient, newCiphertext)
	require.NoError(t, err)
	require.Equal(t, []byte("secret2"), got2)
}

func TestProvider_Rotate_TwiceKeepsBothOlderIdentities(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identities")
	p := &Provider{IdentityPath: path}

	r1, err := p.Recipient()
	require.NoError(t, err)
	c1, err := p.Encrypt(context.Background(), r1, []byte("v1"))
	require.NoError(t, err)

	r2, err := p.Rotate()
	require.NoError(t, err)
	c2, err := p.Encrypt(context.Background(), r2, []byte("v2"))
	require.NoError(t, err)

	r3, err := p.Rotate()
	require.NoError(t, err)

	got1, err := p.Decrypt(context.Background(), r1, c1)
	require.NoError(t, err)
	require.Equal(t, []byte("v1"), got1)

	got2, err := p.Decrypt(context.Background(), r2, c2)
	require.NoError(t, err)
	require.Equal(t, []byte("v2"), got2)

	current, err := p.Recipient()
	require.NoError(t, err)
	require.Equal(t, r3, current)
}

func TestProvider_Decrypt_UnknownKeyIDFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identities")
	p := &Provider{IdentityPath: path}
	_, err := p.Recipient()
	require.NoError(t, err)

	_, err = p.Decrypt(context.Background(), "age1thisdoesnotexist", []byte("ciphertext"))
	require.ErrorContains(t, err, "no stored identity")
}

func TestIdentityPathEnvVar_OverridesDefault(t *testing.T) {
	custom := filepath.Join(t.TempDir(), "custom-identities")
	t.Setenv(IdentityPathEnvVar, custom)

	p, err := New()
	require.NoError(t, err)
	require.Equal(t, custom, p.IdentityPath)
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/keyservice/local/... -v`
Expected: FAIL to compile — `Rotate`, `IdentityPathEnvVar` don't exist yet, and `Decrypt`'s current implementation ignores `keyID` so `TestProvider_Decrypt_UnknownKeyIDFails` wouldn't fail the way the test expects even if it compiled.

- [ ] **Step 4: Rewrite `local.go`**

Replace the full contents of `internal/keyservice/local/local.go`:

```go
// Package local implements git-vault's first real key Provider: a
// single-machine key backed by one or more locally generated age
// identities. It is not a team key-sharing solution — private keys never
// leave the machine they were generated on. It doubles as internal/vault's
// own integration-test fixture, proving the sops <-> keyservice <->
// Provider pipeline end-to-end without needing a real SSO provider built
// first.
//
// Identities are stored one per line in IdentityPath, using the same
// format the real `age` CLI's own identity files use (see
// age.ParseIdentities) — newest last. Encrypt always targets the newest
// identity; Decrypt looks up whichever identity's recipient matches the
// keyID a file was actually sealed under, so older identities keep
// decrypting their own ciphertext after a `rotate` (internal/cli) adds a
// new one.
package local

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// Name is the provider name used in "local:<recipient>" key identifiers
// (see internal/keyservice.Server).
const Name = "local"

// IdentityPathEnvVar overrides the default identities file location (see
// DefaultIdentityPath) when set.
const IdentityPathEnvVar = "GIT_VAULT_LOCAL_IDENTITY_PATH"

// Provider is a Provider backed by one or more locally generated X25519
// age identities persisted at IdentityPath, one per line, newest last.
type Provider struct {
	IdentityPath string
}

// New returns a Provider using IdentityPathEnvVar if set, else the
// default identity path (see DefaultIdentityPath). No identity is
// generated until Recipient, Encrypt, Decrypt, or Rotate is first called.
func New() (*Provider, error) {
	if path := os.Getenv(IdentityPathEnvVar); path != "" {
		return &Provider{IdentityPath: path}, nil
	}
	path, err := DefaultIdentityPath()
	if err != nil {
		return nil, err
	}
	return &Provider{IdentityPath: path}, nil
}

// DefaultIdentityPath returns ~/.cache/git-vault/local/identities
// (honoring $XDG_CACHE_HOME on Linux via os.UserCacheDir).
func DefaultIdentityPath() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "git-vault", "local", "identities"), nil
}

func (p *Provider) Name() string { return Name }

// Recipient returns the newest stored identity's recipient — a bech32
// age public key — generating a first identity if none are stored yet.
func (p *Provider) Recipient() (string, error) {
	ids, err := p.identities()
	if err != nil {
		return "", err
	}
	return ids[len(ids)-1].Recipient().String(), nil
}

// Rotate generates a fresh identity, appends and durably persists it
// alongside any existing ones (older identities are never removed — they
// stay valid for decrypting anything not yet re-sealed with the new one,
// including already-committed ciphertext), and returns its recipient.
// Persisted before returning, not after some later step, so a process
// that dies right after Rotate still leaves the new key durably on disk.
func (p *Provider) Rotate() (string, error) {
	if _, err := p.identities(); err != nil { // ensures the file/dir exist
		return "", err
	}

	id, err := age.GenerateX25519Identity()
	if err != nil {
		return "", fmt.Errorf("local: generate identity: %w", err)
	}
	f, err := os.OpenFile(p.IdentityPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("local: open identities file: %w", err)
	}
	defer f.Close()
	if _, err := f.WriteString(id.String() + "\n"); err != nil {
		return "", fmt.Errorf("local: append identity: %w", err)
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

// Decrypt decrypts armored ciphertext (see Encrypt) using whichever
// stored identity's recipient matches keyID — the file's own sops
// metadata already names exactly which identity encrypted it, so this
// looks it up precisely rather than trying every stored identity.
func (p *Provider) Decrypt(_ context.Context, keyID string, ciphertext []byte) ([]byte, error) {
	ids, err := p.identities()
	if err != nil {
		return nil, err
	}
	var match *age.X25519Identity
	for _, id := range ids {
		if id.Recipient().String() == keyID {
			match = id
			break
		}
	}
	if match == nil {
		return nil, fmt.Errorf("local: no stored identity matches recipient %q", keyID)
	}

	ar := armor.NewReader(bytes.NewReader(ciphertext))
	r, err := age.Decrypt(ar, match)
	if err != nil {
		return nil, fmt.Errorf("local: decrypt: %w", err)
	}
	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("local: decrypt: %w", err)
	}
	return plaintext, nil
}

// identities loads every identity persisted at p.IdentityPath, generating
// and persisting a single fresh one if the file doesn't exist yet.
func (p *Provider) identities() ([]*age.X25519Identity, error) {
	data, err := os.ReadFile(p.IdentityPath)
	if err == nil {
		parsed, err := age.ParseIdentities(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("local: parse identities: %w", err)
		}
		ids := make([]*age.X25519Identity, 0, len(parsed))
		for _, id := range parsed {
			x, ok := id.(*age.X25519Identity)
			if !ok {
				return nil, fmt.Errorf("local: unsupported identity type %T in %s", id, p.IdentityPath)
			}
			ids = append(ids, x)
		}
		if len(ids) == 0 {
			return nil, fmt.Errorf("local: %s contains no identities", p.IdentityPath)
		}
		return ids, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("local: read identities: %w", err)
	}

	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("local: generate identity: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(p.IdentityPath), 0o700); err != nil {
		return nil, fmt.Errorf("local: create identity dir: %w", err)
	}
	if err := os.WriteFile(p.IdentityPath, []byte(id.String()+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("local: write identities: %w", err)
	}
	return []*age.X25519Identity{id}, nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/keyservice/local/... -v`
Expected: PASS — all tests, old (`TestProvider_Name`,
`TestProvider_RecipientGeneratesAndPersistsIdentity`,
`TestProvider_EncryptDecryptRoundTrip`,
`TestProvider_Decrypt_WrongIdentityFails`, the two renamed path tests) and
new.

- [ ] **Step 6: Run the whole project's test suite**

Run: `go build ./... && go test ./...`
Expected: PASS — `internal/cli/vault.go`'s `newLocalVault` calls
`local.New()`/`provider.Recipient()` with unchanged signatures, so nothing
else should break.

- [ ] **Step 7: Commit**

```bash
git add internal/keyservice/local/local.go internal/keyservice/local/local_test.go
git commit -m "feat: multi-identity support + rotation for local provider"
```

---

### Task 3: `git vault rotate` command

**Files:**
- Create: `internal/cli/rotate.go`
- Create: `internal/cli/rotate_test.go`
- Modify: `internal/cli/root.go`

**Interfaces:**
- Consumes: `passphrase.New`/`NewWithSecret`/`PromptNewSecret`/`SetPromptForTesting`/`Name`/`KeyID` (Task 1), `local.New`/`Name` and `(*local.Provider).Rotate` (Task 2), `vaultForProvider`/`loadConfig` (`internal/cli/vault.go`, unchanged), `gitattr.Tracked`, `trackedFiles` (`internal/cli/status.go`, unchanged), `keyservice.NewRegistry`/`NewServer`, `vault.New`.
- Produces: `newRotateCmd() *cobra.Command`, wired into `NewRootCmd()`.

- [ ] **Step 1: Write failing tests for `rotate`**

Create `internal/cli/rotate_test.go`:

```go
package cli

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/keyservice/local"
	"github.com/ducduyn31/git-vault/internal/keyservice/passphrase"
)

func TestRotateCmd_Local_RoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	original := setupTrackedEncryptedFile(t, local.Name)

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{"rotate"})
	require.NoError(t, cmd.Execute())
	require.Contains(t, out.String(), "Rotated 1 file")

	// Provider name is unchanged — rotate never writes .git-vault.yaml.
	cfg, err := config.Load(config.DefaultFileName)
	require.NoError(t, err)
	require.Equal(t, local.Name, cfg.Provider)

	// Prove the file actually opens under the NEW identity, not just that
	// the command exited 0.
	decryptCmd := NewRootCmd()
	decryptCmd.SetOut(&bytes.Buffer{})
	decryptCmd.SetArgs([]string{"decrypt", "secret.yaml"})
	require.NoError(t, decryptCmd.Execute())

	opened, err := os.ReadFile("secret.yaml")
	require.NoError(t, err)
	require.Equal(t, original, string(opened))

	// A second rotate still works — the identity list keeps growing.
	cmd2 := NewRootCmd()
	out2 := &bytes.Buffer{}
	cmd2.SetOut(out2)
	cmd2.SetArgs([]string{"rotate"})
	require.NoError(t, cmd2.Execute())
	require.Contains(t, out2.String(), "Rotated 1 file")
}

func TestRotateCmd_Passphrase_RoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(passphrase.EnvVar, "old passphrase")
	chdirTemp(t)
	original := setupTrackedEncryptedFile(t, passphrase.Name)

	restore := passphrase.SetPromptForTesting(func() (string, error) { return "new passphrase", nil })
	defer restore()

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{"rotate"})
	require.NoError(t, cmd.Execute())
	require.Contains(t, out.String(), "Rotated 1 file")

	// Now that the file is sealed under "new passphrase", the old env var
	// value alone can no longer open it...
	decryptWithOld := NewRootCmd()
	decryptWithOld.SetOut(&bytes.Buffer{})
	decryptWithOld.SetArgs([]string{"decrypt", "secret.yaml"})
	require.Error(t, decryptWithOld.Execute())

	// ...but the new one does.
	t.Setenv(passphrase.EnvVar, "new passphrase")
	decryptCmd := NewRootCmd()
	decryptCmd.SetOut(&bytes.Buffer{})
	decryptCmd.SetArgs([]string{"decrypt", "secret.yaml"})
	require.NoError(t, decryptCmd.Execute())

	opened, err := os.ReadFile("secret.yaml")
	require.NoError(t, err)
	require.Equal(t, original, string(opened))
}

func TestRotateCmd_Passphrase_MismatchedConfirmationFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(passphrase.EnvVar, "old passphrase")
	chdirTemp(t)
	setupTrackedEncryptedFile(t, passphrase.Name)

	calls := 0
	restore := passphrase.SetPromptForTesting(func() (string, error) {
		calls++
		if calls == 1 {
			return "first entry", nil
		}
		return "second entry", nil
	})
	defer restore()

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"rotate"})
	err := cmd.Execute()
	require.ErrorContains(t, err, "did not match")

	// Nothing was touched: the file is still sealed under the original
	// passphrase.
	sealed, err := os.ReadFile("secret.yaml")
	require.NoError(t, err)
	require.Contains(t, string(sealed), "ENC[")
}

func TestRotateCmd_NoTrackedFiles(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	require.NoError(t, config.Save(config.DefaultFileName, config.Config{Provider: local.Name}))

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{"rotate"})
	require.NoError(t, cmd.Execute())
	require.Contains(t, out.String(), "Rotated 0 file")
}

func TestRotateCmd_MissingConfigFails(t *testing.T) {
	chdirTemp(t)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"rotate"})

	err := cmd.Execute()
	require.ErrorContains(t, err, "git vault install")
}

func TestRotateCmd_UnknownProviderFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	require.NoError(t, config.Save(config.DefaultFileName, config.Config{Provider: "bogus"}))

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"rotate"})

	err := cmd.Execute()
	require.ErrorContains(t, err, `unknown provider "bogus"`)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/cli/... -run TestRotateCmd -v`
Expected: FAIL to compile — `newRotateCmd`/the `"rotate"` subcommand don't
exist yet.

- [ ] **Step 3: Create `rotate.go`**

Create `internal/cli/rotate.go`:

```go
package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/gitattr"
	"github.com/ducduyn31/git-vault/internal/keyservice"
	"github.com/ducduyn31/git-vault/internal/keyservice/local"
	"github.com/ducduyn31/git-vault/internal/keyservice/passphrase"
	"github.com/ducduyn31/git-vault/internal/vault"
)

// newRotateCmd re-seals every tracked file under fresh key material for
// the repo's *current* provider — unlike migrate, the provider name never
// changes, so .git-vault.yaml is never rewritten. See
// docs/superpowers/specs/2026-07-11-provider-key-rotation-design.md.
func newRotateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rotate",
		Short: "Generate a new key and re-seal all tracked files under it",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}

			oldVault, _, err := vaultForProvider(cfg.Provider)
			if err != nil {
				return fmt.Errorf("git vault rotate: %w", err)
			}

			var newVault *vault.Vault
			var newRecipients []string
			switch cfg.Provider {
			case local.Name:
				provider, err := local.New()
				if err != nil {
					return fmt.Errorf("git vault rotate: %w", err)
				}
				if _, err := provider.Rotate(); err != nil {
					return fmt.Errorf("git vault rotate: %w", err)
				}
				// One vault now serves both roles: Decrypt matches
				// whichever stored identity a file names, and the
				// freshly rotated identity is the newest, so Encrypt
				// targets it.
				newVault, newRecipients, err = vaultForProvider(local.Name)
				if err != nil {
					return fmt.Errorf("git vault rotate: %w", err)
				}
				oldVault = newVault
			case passphrase.Name:
				newSecret, err := passphrase.PromptNewSecret(cmd.OutOrStdout())
				if err != nil {
					return fmt.Errorf("git vault rotate: %w", err)
				}
				registry := keyservice.NewRegistry()
				if err := registry.Register(passphrase.NewWithSecret(newSecret)); err != nil {
					return fmt.Errorf("git vault rotate: %w", err)
				}
				newVault = vault.New(keyservice.NewServer(registry))
				newRecipients = []string{passphrase.Name + ":" + passphrase.KeyID}
			default:
				return fmt.Errorf("git vault rotate: rotation not supported for provider %q", cfg.Provider)
			}

			patterns, err := gitattr.Tracked(".gitattributes")
			if err != nil {
				return fmt.Errorf("git vault rotate: %w", err)
			}
			var files []string
			if len(patterns) > 0 {
				files, err = trackedFiles(patterns)
				if err != nil {
					return fmt.Errorf("git vault rotate: %w", err)
				}
			}

			for _, f := range files {
				if err := oldVault.Open(f); err != nil {
					return fmt.Errorf("git vault rotate: decrypt %s: %w", f, err)
				}
				if err := newVault.Seal(f, newRecipients); err != nil {
					return fmt.Errorf("git vault rotate: re-seal %s: %w", f, err)
				}
			}

			var followUp string
			switch cfg.Provider {
			case local.Name:
				followUp = "Old identity is retained to decrypt anything not yet migrated (including committed history)."
			case passphrase.Name:
				followUp = "Distribute the new passphrase to your team out-of-band, and keep GIT_VAULT_PASSPHRASE set to the old value followed by the new value (one per line) until everyone has migrated — then the old line can be dropped."
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(),
				"Rotated %d file(s) under %q.\n%s\nRun `git add -A && git commit` to finish — committed ciphertext still needs the old key until you do.\n",
				len(files), cfg.Provider, followUp)
			if err != nil {
				return fmt.Errorf("git vault rotate: print summary: %w", err)
			}
			return nil
		},
	}
}
```

- [ ] **Step 4: Wire `rotate` into the root command**

Edit `internal/cli/root.go`, adding `newRotateCmd(),` to the
`root.AddCommand(...)` call:

```go
	root.AddCommand(
		newLoginCmd(),
		newTrackCmd(),
		newInstallCmd(),
		newMigrateCmd(),
		newRotateCmd(),
		newEncryptCmd(),
		newDecryptCmd(),
		newCleanCmd(),
		newSmudgeCmd(),
		newStatusCmd(),
		newVersionCmd(),
	)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/cli/... -run TestRotateCmd -v`
Expected: PASS — all six tests.

- [ ] **Step 6: Run the whole project's test suite**

Run: `go build ./... && go test ./...`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/cli/rotate.go internal/cli/rotate_test.go internal/cli/root.go
git commit -m "feat: add git vault rotate command"
```
