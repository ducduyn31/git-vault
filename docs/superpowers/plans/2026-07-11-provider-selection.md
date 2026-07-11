# Config-Driven Provider Selection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a repo choose between the `local` and `passphrase` key providers via `.git-vault.yaml`, instead of every command hardcoding `local`.

**Architecture:** `internal/cli/vault.go` gains a `newVault()` dispatcher that loads `.git-vault.yaml` (`internal/config`) and switches on its `Provider` field to build either the existing `local` pipeline or a new `passphrase` one; `encrypt`/`decrypt`/`clean`/`smudge` call it instead of the old `newLocalVault()`. `install` gains a `--provider` flag that resolves and prints the right recipient, then persists the choice by writing `.git-vault.yaml`.

**Tech Stack:** Go, cobra (CLI), `gopkg.in/yaml.v3` (config), `filippo.io/age` (already used inside the `local`/`passphrase` providers — this plan doesn't touch that layer), testify (`require`) for tests.

## Global Constraints

- Missing `.git-vault.yaml` is a hard error everywhere it's needed (`encrypt`/`decrypt`/`clean`/`smudge`) — no silent default-to-`local` fallback. This was an explicit user decision during design.
- Rotating/re-encrypting existing ciphertext when a repo's provider changes is explicitly out of scope. Do not add any detection, warning, or blocking for it — `install --provider=X` always just overwrites `.git-vault.yaml`.
- No changes to `internal/keyservice`, `internal/vault`, or the `Provider` interface. This is `internal/cli`-only wiring on top of what already exists.
- No new dependencies — `internal/config`, `internal/keyservice/local`, and `internal/keyservice/passphrase` already exist and are already imported elsewhere in the module.
- `newLocalVault()` in `internal/cli/vault.go` is not renamed or altered — only added to.

---

### Task 1: Provider dispatch (`newVault`, `vaultForProvider`, `loadConfig`, `newPassphraseVault`)

**Files:**
- Modify: `internal/cli/vault.go` (append new functions after existing `newLocalVault`)
- Test: `internal/cli/vault_test.go` (append new tests)

**Interfaces:**
- Consumes: `local.New() (*local.Provider, error)`, `local.Name` (const `"local"`), `(*local.Provider).Recipient() (string, error)` — all already exist. `passphrase.New() passphrase.Provider`, `passphrase.Name` (const `"passphrase"`), `passphrase.KeyID` (const `"shared"`), `passphrase.EnvVar` (const `"GIT_VAULT_PASSPHRASE"`) — all already exist in `internal/keyservice/passphrase/passphrase.go`. `keyservice.NewRegistry()`, `(*keyservice.Registry).Register(keyservice.Provider) error`, `keyservice.NewServer(*keyservice.Registry) *keyservice.Server` — already exist. `config.Load(path string) (config.Config, error)`, `config.DefaultFileName` (const `".git-vault.yaml"`), `config.Config{Provider string}` — already exist in `internal/config/config.go`. `chdirTemp(t *testing.T)` — test helper already defined in `internal/cli/install_test.go`, same package.
- Produces: `newPassphraseVault() (*vault.Vault, []string, error)`, `vaultForProvider(name string) (*vault.Vault, []string, error)`, `loadConfig() (config.Config, error)`, `newVault() (*vault.Vault, []string, error)` — Task 2 and Task 3 call `newVault()`; `vaultForProvider` is not consumed elsewhere in this plan but is kept as a separately-testable unit (see rationale below).

- [ ] **Step 1: Write the failing tests**

Append to `internal/cli/vault_test.go`:

```go
func TestVaultForProvider_Passphrase(t *testing.T) {
	t.Setenv(passphrase.EnvVar, "correct horse battery staple")

	v, recipients, err := vaultForProvider(passphrase.Name)
	require.NoError(t, err)
	require.NotNil(t, v)
	require.Equal(t, []string{"passphrase:shared"}, recipients)
}

func TestVaultForProvider_UnknownProviderFails(t *testing.T) {
	_, _, err := vaultForProvider("bogus")
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

`vault_test.go` currently imports `"strings"`, `"testing"`, and `require` (for the pre-existing `TestNewLocalVault_ReturnsVaultAndRecipient`, which uses `strings.HasPrefix` — keep it). Replace its import block with the merged version, adding the two new imports the tests above need:

```go
import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/keyservice/passphrase"
)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/cli/... -run 'TestVaultForProvider|TestNewVault' -v`
Expected: FAIL — build error, `undefined: vaultForProvider` / `undefined: newVault` (these functions don't exist yet).

- [ ] **Step 3: Implement the dispatch functions**

Replace the full contents of `internal/cli/vault.go` with:

```go
package cli

import (
	"fmt"
	"os"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/keyservice"
	"github.com/ducduyn31/git-vault/internal/keyservice/local"
	"github.com/ducduyn31/git-vault/internal/keyservice/passphrase"
	"github.com/ducduyn31/git-vault/internal/vault"
)

// newLocalVault builds a Vault dispatching to this machine's local age
// identity, along with the "<provider>:<key-id>" recipient string that
// identity resolves to.
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

// newPassphraseVault builds a Vault dispatching to the shared secret in
// passphrase.EnvVar, along with its fixed "<provider>:<key-id>" recipient
// string.
func newPassphraseVault() (*vault.Vault, []string, error) {
	provider := passphrase.New()

	registry := keyservice.NewRegistry()
	if err := registry.Register(provider); err != nil {
		return nil, nil, err
	}
	server := keyservice.NewServer(registry)

	return vault.New(server), []string{passphrase.Name + ":" + passphrase.KeyID}, nil
}

// vaultForProvider builds the Vault for the named provider.
func vaultForProvider(name string) (*vault.Vault, []string, error) {
	switch name {
	case local.Name:
		return newLocalVault()
	case passphrase.Name:
		return newPassphraseVault()
	default:
		return nil, nil, fmt.Errorf("git vault: unknown provider %q in %s", name, config.DefaultFileName)
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
	return vaultForProvider(cfg.Provider)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/cli/... -run 'TestVaultForProvider|TestNewVault|TestNewLocalVault' -v`
Expected: PASS for all (including the pre-existing `TestNewLocalVault_ReturnsVaultAndRecipient`, which is untouched by this change and must keep passing).

- [ ] **Step 5: Commit**

```bash
git add internal/cli/vault.go internal/cli/vault_test.go
git commit -m "feat: add config-driven provider dispatch (local/passphrase)"
```

---

### Task 2: `install --provider` flag writes `.git-vault.yaml`

**Files:**
- Modify: `internal/cli/install.go` (full file replacement below)
- Test: `internal/cli/install_test.go` (append new tests)

**Interfaces:**
- Consumes: `vaultForProvider(name string) (*vault.Vault, []string, error)` from Task 1 — its `[]string` return is already exactly the `"<provider>:<key-id>"` recipient install needs to print (`newLocalVault`/`newPassphraseVault` both return a single-element slice), so install reuses it instead of re-implementing the local/passphrase switch. `config.Save(path string, c config.Config) error`, `config.DefaultFileName`, `config.Config` (from Task 1's imports). `passphrase.Name`, `passphrase.EnvVar`. `local.Name`. `chdirTemp(t *testing.T)` (already defined in this same file).
- Produces: nothing new for later tasks — `install.go`'s `RunE` is the only consumer of what it builds here.

- [ ] **Step 1: Write the failing tests**

Append to `internal/cli/install_test.go`:

```go
func TestInstallCmd_Passphrase_WritesConfigAndRecipient(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(passphrase.EnvVar, "correct horse battery staple")
	chdirTemp(t)

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{"install", "--provider=passphrase"})
	require.NoError(t, cmd.Execute())

	require.Contains(t, out.String(), "Recipient: passphrase:shared")

	cfg, err := config.Load(config.DefaultFileName)
	require.NoError(t, err)
	require.Equal(t, passphrase.Name, cfg.Provider)
}

func TestInstallCmd_Passphrase_MissingEnvVarFailsBeforeGitConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(passphrase.EnvVar, "")
	chdirTemp(t)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"install", "--provider=passphrase"})

	err := cmd.Execute()
	require.ErrorContains(t, err, passphrase.EnvVar)

	_, gitErr := exec.Command("git", "config", "--get", "filter.git-vault.clean").Output()
	require.Error(t, gitErr, "git config must not be set when install fails fast")
}

func TestInstallCmd_UnknownProviderFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"install", "--provider=bogus"})

	err := cmd.Execute()
	require.ErrorContains(t, err, `unknown provider "bogus"`)
}

func TestInstallCmd_DefaultProvider_WritesLocalConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"install"})
	require.NoError(t, cmd.Execute())

	cfg, err := config.Load(config.DefaultFileName)
	require.NoError(t, err)
	require.Equal(t, local.Name, cfg.Provider)
}
```

Add these imports to `internal/cli/install_test.go` (merge with what's already there — the file already imports `"bytes"`, `"os"`, `"os/exec"`, `"strings"`, `"testing"`, and `require`):

```go
"github.com/ducduyn31/git-vault/internal/config"
"github.com/ducduyn31/git-vault/internal/keyservice/local"
"github.com/ducduyn31/git-vault/internal/keyservice/passphrase"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/cli/... -run TestInstallCmd -v`
Expected: FAIL for all four new tests — `--provider` isn't a registered flag yet, so cobra rejects it with `unknown flag: --provider` before `RunE` ever runs. That makes `TestInstallCmd_Passphrase_WritesConfigAndRecipient` fail (no `Recipient:` in output, no `.git-vault.yaml` written), `TestInstallCmd_Passphrase_MissingEnvVarFailsBeforeGitConfig` fail (the error is about the unknown flag, not `GIT_VAULT_PASSPHRASE`), `TestInstallCmd_UnknownProviderFails` fail (error is about the unknown flag, not `unknown provider "bogus"`), and `TestInstallCmd_DefaultProvider_WritesLocalConfig` fail (`config.Load` errors — no file was written).

- [ ] **Step 3: Implement `--provider` and the config write**

Replace the full contents of `internal/cli/install.go` with:

```go
package cli

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/config"
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

			if providerName == passphrase.Name && os.Getenv(passphrase.EnvVar) == "" {
				return fmt.Errorf("git vault install: %s not set", passphrase.EnvVar)
			}

			// vaultForProvider both validates providerName (its default
			// case errors on anything unknown) and resolves the
			// "<provider>:<key-id>" recipient to print, via the same
			// switch newVault() uses at encrypt/decrypt/clean/smudge time
			// — no separate recipient-resolution switch needed here.
			_, recipients, err := vaultForProvider(providerName)
			if err != nil {
				return fmt.Errorf("git vault install: %w", err)
			}
			recipient := recipients[0]

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

			if err := config.Save(config.DefaultFileName, config.Config{Provider: providerName}); err != nil {
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
	cmd.Flags().String("provider", local.Name, "key provider to use (local, passphrase)")
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

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/cli/... -run TestInstallCmd -v`
Expected: PASS for all `TestInstallCmd_*` tests, including the pre-existing `TestInstallCmd_SetsRepoLocalFilterConfig` and `TestInstallCmd_Global_SetsGlobalFilterConfig` (unaffected — they don't assert anything about `.git-vault.yaml`, and still pass a default `--provider`).

- [ ] **Step 5: Commit**

```bash
git add internal/cli/install.go internal/cli/install_test.go
git commit -m "feat: add --provider flag to install, persist choice to .git-vault.yaml"
```

---

### Task 3: Wire encrypt/decrypt/clean/smudge to `newVault()`

**Files:**
- Modify: `internal/cli/encrypt.go:11` (`newLocalVault()` → `newVault()`)
- Modify: `internal/cli/decrypt.go:11` (`newLocalVault()` → `newVault()`)
- Modify: `internal/cli/clean.go:16` (`newLocalVault()` → `newVault()`)
- Modify: `internal/cli/smudge.go:16` (`newLocalVault()` → `newVault()`)
- Modify: `internal/cli/encrypt_test.go` (fix existing round-trip test, add two new tests)
- Modify: `internal/cli/clean_smudge_test.go` (fix existing round-trip test)
- Modify: `internal/cli/status_test.go` (fix `TestStatusCmd_ReportsPlaintextThenEncrypted`, which calls `encrypt` without running `install` first)

**Interfaces:**
- Consumes: `newVault()` from Task 1. `NewRootCmd()`, `chdirTemp(t *testing.T)` (existing). `passphrase.EnvVar`, `passphrase.Name` (existing, already used in Tasks 1–2).
- Produces: nothing new for later tasks — this is the last task in the plan.

- [ ] **Step 1: Write/fix the tests first (source files untouched for now)**

Replace the full contents of `internal/cli/encrypt_test.go` with:

```go
package cli

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ducduyn31/git-vault/internal/keyservice/passphrase"
)

func TestEncryptCmd_ThenDecryptCmd_RoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	runInstall(t)

	path := "secret.yaml"
	original := "password: hunter2\n"
	require.NoError(t, os.WriteFile(path, []byte(original), 0o644))

	encryptCmd := NewRootCmd()
	encryptCmd.SetOut(&bytes.Buffer{})
	encryptCmd.SetArgs([]string{"encrypt", path})
	require.NoError(t, encryptCmd.Execute())

	sealed, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NotContains(t, string(sealed), "hunter2")
	require.Contains(t, string(sealed), "password: ENC[")

	decryptCmd := NewRootCmd()
	decryptCmd.SetOut(&bytes.Buffer{})
	decryptCmd.SetArgs([]string{"decrypt", path})
	require.NoError(t, decryptCmd.Execute())

	opened, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, original, string(opened))
}

func TestEncryptCmd_ThenDecryptCmd_PassphraseProvider_RoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(passphrase.EnvVar, "correct horse battery staple")
	chdirTemp(t)
	runInstallWithArgs(t, "--provider="+passphrase.Name)

	path := "secret.yaml"
	original := "password: hunter2\n"
	require.NoError(t, os.WriteFile(path, []byte(original), 0o644))

	encryptCmd := NewRootCmd()
	encryptCmd.SetOut(&bytes.Buffer{})
	encryptCmd.SetArgs([]string{"encrypt", path})
	require.NoError(t, encryptCmd.Execute())

	sealed, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NotContains(t, string(sealed), "hunter2")
	// sops embeds the recipient identifier in cleartext metadata (it isn't
	// secret) — asserting on "passphrase:shared" here, rather than just a
	// successful round-trip, is what actually proves the passphrase
	// provider was used and not local (which would also round-trip fine).
	require.Contains(t, string(sealed), "passphrase:shared")

	decryptCmd := NewRootCmd()
	decryptCmd.SetOut(&bytes.Buffer{})
	decryptCmd.SetArgs([]string{"decrypt", path})
	require.NoError(t, decryptCmd.Execute())

	opened, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, original, string(opened))
}

func TestEncryptCmd_MissingConfigFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	path := "secret.yaml"
	require.NoError(t, os.WriteFile(path, []byte("password: hunter2\n"), 0o644))

	encryptCmd := NewRootCmd()
	encryptCmd.SetOut(&bytes.Buffer{})
	encryptCmd.SetArgs([]string{"encrypt", path})

	err := encryptCmd.Execute()
	require.ErrorContains(t, err, "git vault install")
}
```

Add these two small helpers to `internal/cli/install_test.go` (they belong there since `chdirTemp` already lives in that file, and Task 3's test files need to run `install` as setup without repeating the same four lines everywhere):

```go
func runInstall(t *testing.T) {
	t.Helper()
	runInstallWithArgs(t)
}

func runInstallWithArgs(t *testing.T, extraArgs ...string) {
	t.Helper()
	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs(append([]string{"install"}, extraArgs...))
	require.NoError(t, cmd.Execute())
}
```

In `internal/cli/clean_smudge_test.go`, replace the full contents with:

```go
package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCleanCmd_ThenSmudgeCmd_RoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	runInstall(t)

	original := "password: hunter2\n"

	cleanCmd := NewRootCmd()
	sealed := &bytes.Buffer{}
	cleanCmd.SetIn(strings.NewReader(original))
	cleanCmd.SetOut(sealed)
	cleanCmd.SetArgs([]string{"clean", "secret.yaml"})
	require.NoError(t, cleanCmd.Execute())

	require.NotContains(t, sealed.String(), "hunter2")
	require.Contains(t, sealed.String(), "password: ENC[")

	smudgeCmd := NewRootCmd()
	opened := &bytes.Buffer{}
	smudgeCmd.SetIn(bytes.NewReader(sealed.Bytes()))
	smudgeCmd.SetOut(opened)
	smudgeCmd.SetArgs([]string{"smudge", "secret.yaml"})
	require.NoError(t, smudgeCmd.Execute())

	require.Equal(t, original, opened.String())
}
```

In `internal/cli/status_test.go`, in `TestStatusCmd_ReportsPlaintextThenEncrypted`, insert a call to `runInstall(t)` right after `chdirTemp(t)` (before the `trackCmd` block):

```go
func TestStatusCmd_ReportsPlaintextThenEncrypted(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	runInstall(t)

	trackCmd := NewRootCmd()
	trackCmd.SetOut(&bytes.Buffer{})
	trackCmd.SetArgs([]string{"track", "secret.yaml"})
	require.NoError(t, trackCmd.Execute())

	require.NoError(t, os.WriteFile("secret.yaml", []byte("password: hunter2\n"), 0o644))
	require.NoError(t, exec.Command("git", "add", "secret.yaml").Run())

	plainOut := &bytes.Buffer{}
	statusCmd := NewRootCmd()
	statusCmd.SetOut(plainOut)
	statusCmd.SetArgs([]string{"status"})
	require.NoError(t, statusCmd.Execute())
	require.Contains(t, plainOut.String(), "secret.yaml\tplaintext")

	encryptCmd := NewRootCmd()
	encryptCmd.SetOut(&bytes.Buffer{})
	encryptCmd.SetArgs([]string{"encrypt", "secret.yaml"})
	require.NoError(t, encryptCmd.Execute())

	sealedOut := &bytes.Buffer{}
	statusCmd = NewRootCmd()
	statusCmd.SetOut(sealedOut)
	statusCmd.SetArgs([]string{"status"})
	require.NoError(t, statusCmd.Execute())
	require.Contains(t, sealedOut.String(), "secret.yaml\tencrypted")
}
```

(`TestStatusCmd_NoGitattributes_ReportsNothingTracked`, the other test in this file, never calls `encrypt`/`decrypt`/`clean`/`smudge` — leave it untouched.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/cli/... -v`
Expected: at this point `encrypt.go`/`decrypt.go`/`clean.go`/`smudge.go` still call the old `newLocalVault()` (unmodified), which ignores `.git-vault.yaml` entirely, so:
- `TestEncryptCmd_MissingConfigFails` FAILS — `encryptCmd.Execute()` returns `nil` (no error), so `require.ErrorContains(t, err, "git vault install")` fails.
- `TestEncryptCmd_ThenDecryptCmd_PassphraseProvider_RoundTrip` FAILS — `newLocalVault()` still seals with the local age recipient, so the sealed file contains `local:...`, not `passphrase:shared`, and `require.Contains(t, string(sealed), "passphrase:shared")` fails.
- `TestEncryptCmd_ThenDecryptCmd_RoundTrip`, `TestCleanCmd_ThenSmudgeCmd_RoundTrip`, and `TestStatusCmd_ReportsPlaintextThenEncrypted` PASS even before Step 3 — they only added a `runInstall(t)` setup call and don't assert on which provider was used, so `newLocalVault()`'s old behavior already satisfies them. That's expected: those three are regression-safety tests for this task, not new-behavior tests.

- [ ] **Step 3: Apply the source edits**

In `internal/cli/encrypt.go`, change:

```go
			v, recipients, err := newLocalVault()
```

to:

```go
			v, recipients, err := newVault()
```

In `internal/cli/decrypt.go`, change:

```go
			v, _, err := newLocalVault()
```

to:

```go
			v, _, err := newVault()
```

In `internal/cli/clean.go`, change:

```go
			v, recipients, err := newLocalVault()
```

to:

```go
			v, recipients, err := newVault()
```

In `internal/cli/smudge.go`, change:

```go
			v, _, err := newLocalVault()
```

to:

```go
			v, _, err := newVault()
```

- [ ] **Step 4: Verify everything compiles and passes together**

Run: `go build ./... && go vet ./... && gofmt -l .`
Expected: no output from any of the three commands.

Run: `go test ./... -v`
Expected: PASS across the whole module — every existing test plus every test added in Tasks 1–3, including the two that were failing at Step 2.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/encrypt.go internal/cli/decrypt.go internal/cli/clean.go internal/cli/smudge.go \
        internal/cli/encrypt_test.go internal/cli/clean_smudge_test.go internal/cli/status_test.go \
        internal/cli/install_test.go
git commit -m "feat: wire encrypt/decrypt/clean/smudge to config-driven provider selection"
```

---

## Final Verification

- [ ] Run `go build ./... && go vet ./... && gofmt -l . && go test ./...` one more time from the repo root. All must pass with zero `gofmt -l` output.
- [ ] Manually sanity-check the passphrase path end to end in a scratch directory:
  ```bash
  rm -rf /tmp/gv-manual-check && mkdir /tmp/gv-manual-check && cd /tmp/gv-manual-check
  git init
  export GIT_VAULT_PASSPHRASE="correct horse battery staple"
  go run github.com/ducduyn31/git-vault/cmd/git-vault install --provider=passphrase
  cat .git-vault.yaml   # expect: provider: passphrase
  echo "password: hunter2" > secret.yaml
  go run github.com/ducduyn31/git-vault/cmd/git-vault encrypt secret.yaml
  cat secret.yaml       # expect: password: ENC[...]
  go run github.com/ducduyn31/git-vault/cmd/git-vault decrypt secret.yaml
  cat secret.yaml       # expect: password: hunter2
  ```
