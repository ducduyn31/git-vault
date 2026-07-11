# CLI: wiring encrypt/decrypt/clean/smudge/install Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the `encrypt`, `decrypt`, `clean`, `smudge`, and `install` CLI subcommands (currently stubs returning `"not implemented in scaffold"`) to the already-real `internal/vault.Vault` + `internal/keyservice.Server` + `internal/keyservice/local.Provider` pipeline, per `docs/superpowers/specs/2026-07-11-cli-vault-wiring-design.md`.

**Architecture:** A new `internal/cli/vault.go` helper (`newLocalVault`) builds the vault/keyservice/registry/provider wiring once, shared by `encrypt`/`decrypt`/`clean`/`smudge`. `install` shells out to `git config` to register the filter driver. `internal/vault`'s `SealStream`/`OpenStream` each gain an idempotency passthrough check so git re-invoking a filter on already-transformed content doesn't double-encrypt or hard-error.

**Tech Stack:** Go 1.26.5 (unchanged), `github.com/spf13/cobra`, `github.com/stretchr/testify/require`, `github.com/getsops/sops/v3` (already a dependency), stdlib `os/exec` for shelling out to `git config`. No new modules are added and no `go.mod`/`go.sum` changes occur in this plan.

## Global Constraints

- Recipients are always resolved live via `local.New().Recipient()`, prefixed as `"local:" + recipient` — no repo-tracked recipients list, no new `.git-vault.yaml` field, no "add a recipient" command. Multi-recipient/team support is out of scope (per the design's non-goals).
- No `diff.git-vault.textconv` driver is configured by `install` — filter config only.
- `login` and `status` are untouched — they remain stubs returning `"not implemented in scaffold"`.
- `install` always sets `filter.git-vault.required = true` (fail-closed, per `docs/superpowers/specs/2026-07-10-git-vault-ux-safety-design.md`).
- `clean`/`smudge`'s `Args` changes from `cobra.MaximumNArgs(1)` to `cobra.ExactArgs(1)` — git always supplies `%f`, and format detection requires it.
- The "already sealed/already plain, pass through unchanged" idempotency check lives inside `internal/vault`'s `SealStream`/`OpenStream` themselves, not duplicated in the CLI layer.
- Every test that generates/loads a local age identity or touches git config must isolate `$HOME` via `t.Setenv("HOME", t.TempDir())` first — never touch a real machine's `~/.cache/git-vault` identity or `~/.gitconfig`.
- All test files use `github.com/stretchr/testify/require` for assertions.
- Every Go-code-touching task ends with `gofumpt -l -w .` before committing.

---

### Task 1: `internal/vault` — idempotency passthrough in `SealStream`/`OpenStream`

**Files:**
- Modify: `internal/vault/vault.go`
- Modify: `internal/vault/vault_test.go`

**Interfaces:**
- Consumes: nothing new (uses the existing `store.LoadEncryptedFile` already imported via `storeForFormat`).
- Produces: no signature change to `SealStream`/`OpenStream` — same `func (v *Vault) SealStream(w io.Writer, r io.Reader, format Format, recipients []string) error` / `func (v *Vault) OpenStream(w io.Writer, r io.Reader, format Format) error`, only their internal behavior changes. Task 4 relies on this passthrough behavior for `clean`/`smudge`.

- [ ] **Step 1: Write the failing tests**

Add to `internal/vault/vault_test.go`. First add `"bytes"` to the import block (it currently imports `"encoding/json"`, `"os"`, `"path/filepath"`, `"strings"`, `"testing"`, `testify/require`, `yamlv3`, `keyservice`, `keyservice/local`):

```go
import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	yamlv3 "gopkg.in/yaml.v3"

	"github.com/ducduyn31/git-vault/internal/keyservice"
	"github.com/ducduyn31/git-vault/internal/keyservice/local"
)
```

Then append these two tests at the end of the file:

```go
func TestSealStream_AlreadySealed_PassesThrough(t *testing.T) {
	v, recipients := newTestVault(t)

	plaintext := "database:\n  password: hunter2\n"
	var sealed bytes.Buffer
	require.NoError(t, v.SealStream(&sealed, strings.NewReader(plaintext), FormatYAML, recipients))

	var out bytes.Buffer
	require.NoError(t, v.SealStream(&out, bytes.NewReader(sealed.Bytes()), FormatYAML, recipients))

	require.Equal(t, sealed.Bytes(), out.Bytes())
}

func TestOpenStream_AlreadyPlain_PassesThrough(t *testing.T) {
	v, _ := newTestVault(t)

	plaintext := "database:\n  password: hunter2\n"
	var out bytes.Buffer
	require.NoError(t, v.OpenStream(&out, strings.NewReader(plaintext), FormatYAML))

	require.Equal(t, plaintext, out.String())
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/vault/... -run 'TestSealStream_AlreadySealed_PassesThrough|TestOpenStream_AlreadyPlain_PassesThrough' -v`

Expected: both FAIL — `TestSealStream_AlreadySealed_PassesThrough` fails the `require.Equal` (sealing already-sealed content produces a different, double-wrapped tree, not the original bytes); `TestOpenStream_AlreadyPlain_PassesThrough` fails `require.NoError` (current `OpenStream` returns a `"vault: parse ciphertext"` error because the plaintext has no `sops` metadata block).

- [ ] **Step 3: Implement the passthrough checks**

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
	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/age"
	sopskeyservice "github.com/getsops/sops/v3/keyservice"

	"github.com/ducduyn31/git-vault/internal/keyservice"
)

// sopsVersion is written into new files' sops.version metadata field. It
// is a plain literal, not sops's own version.Version const, because that
// package imports github.com/urfave/cli purely for its CLI-version-check
// subcommand — a dependency this plan otherwise avoids. Keep this in sync
// with the github.com/getsops/sops/v3 version pinned in go.mod.
const sopsVersion = "3.13.2"

// Vault seals/opens files using sops, dispatching key operations to a
// keyservice.Server in-process via sopskeyservice.NewCustomLocalClient.
type Vault struct {
	clients []sopskeyservice.KeyServiceClient
}

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
// to w. Used by git's clean filter, which gets file content on
// stdin/stdout rather than a real path.
//
// If r is already a valid sops-encrypted document for format, it is
// written through to w unchanged instead of being sealed again — git can
// re-invoke clean on already-sealed content (e.g. during a merge/rebase
// re-apply), and sealing it a second time would double-wrap it.
func (v *Vault) SealStream(w io.Writer, r io.Reader, format Format, recipients []string) error {
	if len(recipients) == 0 {
		return fmt.Errorf("vault: seal: no recipients provided")
	}

	plaintext, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("vault: read plaintext: %w", err)
	}

	store := storeForFormat(format)

	if _, err := store.LoadEncryptedFile(plaintext); err == nil {
		if _, err := w.Write(plaintext); err != nil {
			return fmt.Errorf("vault: write ciphertext: %w", err)
		}
		return nil
	}

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
// w. Used by git's smudge filter.
//
// If r has no sops metadata for format (e.g. a file committed before
// git-vault install was ever run), it is written through to w unchanged
// instead of erroring — only a failure decrypting an actual sops tree
// (bad key, tampered MAC) is a real error.
func (v *Vault) OpenStream(w io.Writer, r io.Reader, format Format) error {
	ciphertext, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("vault: read ciphertext: %w", err)
	}

	store := storeForFormat(format)
	tree, err := store.LoadEncryptedFile(ciphertext)
	if err != nil {
		if _, err := w.Write(ciphertext); err != nil {
			return fmt.Errorf("vault: write plaintext: %w", err)
		}
		return nil
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

- [ ] **Step 4: Run the full vault suite to verify it passes**

Run: `go test ./internal/vault/... -v`

Expected: PASS — all 9 tests (the 7 pre-existing round-trip/error tests plus the 2 new passthrough tests).

- [ ] **Step 5: Format and commit**

Run: `gofumpt -l -w .`

```bash
git add internal/vault/vault.go internal/vault/vault_test.go
git commit -m "feat: pass through already-sealed/already-plain content in SealStream/OpenStream"
```

---

### Task 2: `internal/cli` — shared `newLocalVault` helper

**Files:**
- Create: `internal/cli/vault.go`
- Create: `internal/cli/vault_test.go`

**Interfaces:**
- Consumes: `local.New() (*local.Provider, error)`, `local.Name` (const `"local"`), `(*local.Provider).Recipient() (string, error)` (all from `internal/keyservice/local`); `keyservice.NewRegistry() *Registry`, `(*Registry).Register(p Provider) error`, `keyservice.NewServer(r *Registry) *Server` (from `internal/keyservice`); `vault.New(server *keyservice.Server) *Vault` (from `internal/vault`, Task 1).
- Produces: `newLocalVault() (*vault.Vault, []string, error)` — used by Tasks 3 and 4.

- [ ] **Step 1: Write the failing test**

Create `internal/cli/vault_test.go`:

```go
package cli

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewLocalVault_ReturnsVaultAndRecipient(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	v, recipients, err := newLocalVault()
	require.NoError(t, err)
	require.NotNil(t, v)
	require.Len(t, recipients, 1)
	require.True(t, strings.HasPrefix(recipients[0], "local:"))
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/cli/... -run TestNewLocalVault_ReturnsVaultAndRecipient -v`

Expected: FAIL to compile — `newLocalVault` undefined.

- [ ] **Step 3: Implement the helper**

Create `internal/cli/vault.go`:

```go
package cli

import (
	"github.com/ducduyn31/git-vault/internal/keyservice"
	"github.com/ducduyn31/git-vault/internal/keyservice/local"
	"github.com/ducduyn31/git-vault/internal/vault"
)

// newLocalVault builds a Vault dispatching to this machine's local age
// identity, along with the "<provider>:<key-id>" recipient string that
// identity resolves to. Every command that seals or opens a file
// (encrypt, decrypt, clean, smudge) shares this instead of repeating the
// provider/registry/server wiring.
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
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/cli/... -run TestNewLocalVault_ReturnsVaultAndRecipient -v`

Expected: PASS

- [ ] **Step 5: Format and commit**

Run: `gofumpt -l -w .`

```bash
git add internal/cli/vault.go internal/cli/vault_test.go
git commit -m "feat: add shared local-vault helper for CLI commands"
```

---

### Task 3: Wire `encrypt` and `decrypt`

**Files:**
- Modify: `internal/cli/encrypt.go`
- Modify: `internal/cli/decrypt.go`
- Modify: `internal/cli/root_test.go` (remove `"encrypt"` and `"decrypt"` from `TestStubCommands_NotImplemented`'s cases)
- Create: `internal/cli/encrypt_test.go`

**Interfaces:**
- Consumes: `newLocalVault() (*vault.Vault, []string, error)` (Task 2); `(*vault.Vault).Seal(path string, recipients []string) error`, `(*vault.Vault).Open(path string) error` (already implemented in `internal/vault`).
- Produces: nothing new consumed by later tasks.

- [ ] **Step 1: Write the failing round-trip test**

Create `internal/cli/encrypt_test.go`:

```go
package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncryptCmd_ThenDecryptCmd_RoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	path := filepath.Join(t.TempDir(), "secret.yaml")
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/cli/... -run TestEncryptCmd_ThenDecryptCmd_RoundTrip -v`

Expected: FAIL — `encryptCmd.Execute()` returns the `"git vault encrypt: not implemented in scaffold"` error, so `require.NoError` fails.

- [ ] **Step 3: Implement `encrypt` and `decrypt`**

Replace `internal/cli/encrypt.go`:

```go
package cli

import "github.com/spf13/cobra"

func newEncryptCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "encrypt <file>",
		Short: "Encrypt a file in place, outside the filter path",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, recipients, err := newLocalVault()
			if err != nil {
				return err
			}
			return v.Seal(args[0], recipients)
		},
	}
}
```

Replace `internal/cli/decrypt.go`:

```go
package cli

import "github.com/spf13/cobra"

func newDecryptCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "decrypt <file>",
		Short: "Decrypt a file in place, outside the filter path",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, _, err := newLocalVault()
			if err != nil {
				return err
			}
			return v.Open(args[0])
		},
	}
}
```

- [ ] **Step 4: Remove `encrypt`/`decrypt` from the stub-command test**

Edit `internal/cli/root_test.go`: remove the `{"encrypt", []string{"encrypt", "file.txt"}},` and `{"decrypt", []string{"decrypt", "file.txt"}},` lines from the `cases` slice in `TestStubCommands_NotImplemented`.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/cli/... -v`

Expected: all tests in `internal/cli` `ok`, including `TestEncryptCmd_ThenDecryptCmd_RoundTrip` and the trimmed `TestStubCommands_NotImplemented`.

- [ ] **Step 6: Format and commit**

Run: `gofumpt -l -w .`

```bash
git add internal/cli/encrypt.go internal/cli/decrypt.go internal/cli/encrypt_test.go internal/cli/root_test.go
git commit -m "feat: wire git vault encrypt/decrypt to the real vault"
```

---

### Task 4: Wire `clean` and `smudge`

**Files:**
- Modify: `internal/cli/clean.go`
- Modify: `internal/cli/smudge.go`
- Modify: `internal/cli/root_test.go` (remove `"clean"` and `"smudge"` from `TestStubCommands_NotImplemented`'s cases)
- Create: `internal/cli/clean_smudge_test.go`

**Interfaces:**
- Consumes: `newLocalVault() (*vault.Vault, []string, error)` (Task 2); `(*vault.Vault).SealStream(w io.Writer, r io.Reader, format vault.Format, recipients []string) error`, `(*vault.Vault).OpenStream(w io.Writer, r io.Reader, format vault.Format) error`, `vault.FormatForPath(path string) vault.Format` (Task 1/already implemented in `internal/vault`).
- Produces: nothing new consumed by later tasks.

- [ ] **Step 1: Write the failing round-trip test**

Create `internal/cli/clean_smudge_test.go`:

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

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/cli/... -run TestCleanCmd_ThenSmudgeCmd_RoundTrip -v`

Expected: FAIL — `cleanCmd.Execute()` returns the `"git vault clean: not implemented in scaffold"` error.

- [ ] **Step 3: Implement `clean` and `smudge`**

Replace `internal/cli/clean.go`:

```go
package cli

import (
	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/vault"
)

func newCleanCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "clean <path>",
		Short:  "Git clean filter entry point (encrypt on stage)",
		Args:   cobra.ExactArgs(1),
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			v, recipients, err := newLocalVault()
			if err != nil {
				return err
			}
			return v.SealStream(cmd.OutOrStdout(), cmd.InOrStdin(), vault.FormatForPath(args[0]), recipients)
		},
	}
}
```

Replace `internal/cli/smudge.go`:

```go
package cli

import (
	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/vault"
)

func newSmudgeCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "smudge <path>",
		Short:  "Git smudge filter entry point (decrypt on checkout)",
		Args:   cobra.ExactArgs(1),
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			v, _, err := newLocalVault()
			if err != nil {
				return err
			}
			return v.OpenStream(cmd.OutOrStdout(), cmd.InOrStdin(), vault.FormatForPath(args[0]))
		},
	}
}
```

- [ ] **Step 4: Remove `clean`/`smudge` from the stub-command test**

Edit `internal/cli/root_test.go`: remove the `{"clean", []string{"clean", "file.txt"}},` and `{"smudge", []string{"smudge", "file.txt"}},` lines from the `cases` slice in `TestStubCommands_NotImplemented`.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/cli/... -v`

Expected: all tests in `internal/cli` `ok`, including `TestCleanCmd_ThenSmudgeCmd_RoundTrip` and the further-trimmed `TestStubCommands_NotImplemented`.

- [ ] **Step 6: Format and commit**

Run: `gofumpt -l -w .`

```bash
git add internal/cli/clean.go internal/cli/smudge.go internal/cli/clean_smudge_test.go internal/cli/root_test.go
git commit -m "feat: wire git vault clean/smudge to the real vault"
```

---

### Task 5: Wire `install`

**Files:**
- Modify: `internal/cli/install.go`
- Modify: `internal/cli/root_test.go` (remove `"install"` from `TestStubCommands_NotImplemented`'s cases)
- Create: `internal/cli/install_test.go`

**Interfaces:**
- Consumes: `local.New() (*local.Provider, error)`, `(*local.Provider).Recipient() (string, error)` (from `internal/keyservice/local`).
- Produces: nothing consumed by later tasks in this plan (Task 6 is verification only).

- [ ] **Step 1: Write the failing tests**

Create `internal/cli/install_test.go`:

```go
package cli

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func gitConfigGet(t *testing.T, global bool, key string) string {
	t.Helper()
	args := []string{"config"}
	if global {
		args = append(args, "--global")
	}
	args = append(args, "--get", key)
	out, err := exec.Command("git", args...).Output()
	require.NoError(t, err)
	return strings.TrimSpace(string(out))
}

func chdirTemp(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	old, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(old) })
	require.NoError(t, exec.Command("git", "init").Run())
}

func TestInstallCmd_SetsRepoLocalFilterConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"install"})
	require.NoError(t, cmd.Execute())

	require.Equal(t, "git-vault clean %f", gitConfigGet(t, false, "filter.git-vault.clean"))
	require.Equal(t, "git-vault smudge %f", gitConfigGet(t, false, "filter.git-vault.smudge"))
	require.Equal(t, "true", gitConfigGet(t, false, "filter.git-vault.required"))
}

func TestInstallCmd_Global_SetsGlobalFilterConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"install", "--global"})
	require.NoError(t, cmd.Execute())

	require.Equal(t, "true", gitConfigGet(t, true, "filter.git-vault.required"))
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/cli/... -run TestInstallCmd -v`

Expected: both FAIL — `install`'s `RunE` returns `"git vault install: not implemented in scaffold"`.

- [ ] **Step 3: Implement `install`**

Replace `internal/cli/install.go`:

```go
package cli

import (
	"fmt"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/keyservice/local"
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

			provider, err := local.New()
			if err != nil {
				return fmt.Errorf("git vault install: %w", err)
			}
			recipient, err := provider.Recipient()
			if err != nil {
				return fmt.Errorf("git vault install: %w", err)
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

			scope := "repo"
			if global {
				scope = "global"
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Installed git-vault filter driver (%s scope).\nRecipient: %s:%s\n", scope, local.Name, recipient)
			return nil
		},
	}
	cmd.Flags().Bool("global", false, "install the filter driver in the user's global git config")
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

- [ ] **Step 4: Remove `install` from the stub-command test**

Edit `internal/cli/root_test.go`: remove the `{"install", []string{"install"}},` line from the `cases` slice in `TestStubCommands_NotImplemented`. Only `{"login", ...}` and `{"status", ...}` remain.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/cli/... -v`

Expected: all tests `ok`, including both `TestInstallCmd_*` tests and the final, fully-trimmed `TestStubCommands_NotImplemented` (only `login`/`status`).

- [ ] **Step 6: Format and commit**

Run: `gofumpt -l -w .`

```bash
git add internal/cli/install.go internal/cli/install_test.go internal/cli/root_test.go
git commit -m "feat: wire git vault install to register the filter driver"
```

---

### Task 6: Final verification

**Files:** none (verification only).

- [ ] **Step 1: Run the full test suite**

Run: `go test ./... -v`
Expected: every package `ok`, including `internal/vault`, `internal/cli`, `internal/keyservice`, `internal/keyservice/local`, `internal/gitattr`, `internal/session`, `internal/config`.

- [ ] **Step 2: Run go vet**

Run: `go vet ./...`
Expected: no output.

- [ ] **Step 3: Confirm formatting**

Run: `gofumpt -l .`
Expected: no files listed.

- [ ] **Step 4: Run golangci-lint if available**

Run: `task lint` (or `golangci-lint run` directly, e.g. via `nix develop`)
Expected: no issues. If `golangci-lint`/`task` aren't installed locally, skip this step — CI's lint job (`.github/workflows/ci.yml`) covers it.

- [ ] **Step 5: Build the binary and confirm it isn't left behind**

Run: `go build -o git-vault ./cmd/git-vault && rm -f git-vault && git status --porcelain`
Expected: `git status --porcelain` prints nothing (the binary was removed, no other unintended changes).

- [ ] **Step 6: Confirm one commit per task**

Run: `git log --oneline -6`
Expected: 5 commits, one per Task 1–5 above, in order (Task 6 itself makes no commit — verification only).
