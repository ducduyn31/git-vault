# Migrate Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `git vault migrate --provider=<name>`, which re-seals every tracked file from the current provider to a different target provider and updates `.git-vault.yaml`, closing the rotate/migrate non-goal left by the provider-selection spec.

**Architecture:** New `internal/cli/migrate.go` with `newMigrateCmd()`, wired into `root.go`. Reuses `vaultForProvider`/`loadConfig` (`internal/cli/vault.go`) to build the old and new `*vault.Vault`, `gitattr.Tracked` + the existing `trackedFiles` helper (`internal/cli/status.go`) to enumerate files, and each file's existing `Vault.Open`/`Vault.Seal` to re-seal in place.

**Tech Stack:** Go, cobra, `gopkg.in/yaml.v3` (via `internal/config`, unchanged), testify (`require`) for tests. No new dependencies.

## Global Constraints

- `migrate --provider=X` where `X` equals the current provider is a hard error, not a silent no-op — neither `local` nor `passphrase` has two distinct key sources to rotate between (see the design spec's non-goal). Do not attempt same-provider rotation.
- `migrate` never runs `git add`/`git commit` itself — it only re-seals the working tree and prints what to do next.
- Fail fast: `--provider` validation, the same-provider check, and the target-provider build (including the `passphrase` env var check) all happen before any file is opened or `.git-vault.yaml` is written.
- No changes to `internal/keyservice`, `internal/vault`, `internal/config`, or `internal/gitattr` — this is `internal/cli`-only wiring on top of what already exists.
- Test setup uses `config.Save` + `track` directly, not `runInstall` — `install` also sets `filter.git-vault.*` git config pointing at a real `git-vault` binary, and `git add` in a test would try to invoke it (see `status_test.go`'s existing comment on this).

---

### Task 1: `migrate` command

**Files:**
- Create: `internal/cli/migrate.go`
- Create: `internal/cli/migrate_test.go`
- Modify: `internal/cli/root.go` (register `newMigrateCmd()`)

**Interfaces:**
- Consumes: `loadConfig() (config.Config, error)`, `vaultForProvider(name string) (*vault.Vault, []string, error)` (`internal/cli/vault.go`, both already exist). `gitattr.Tracked(path string) ([]string, error)` (already exists). `trackedFiles(patterns []string) ([]string, error)` (already exists in `internal/cli/status.go`, same package). `config.Save(path string, c config.Config) error`, `config.DefaultFileName`, `config.Config{Provider string}` (already exist). `(*vault.Vault).Open(path string) error`, `(*vault.Vault).Seal(path string, recipients []string) error` (already exist). `passphrase.Name`, `passphrase.EnvVar` (already exist). `chdirTemp(t *testing.T)` (already exists in `internal/cli/install_test.go`, same package).
- Produces: `newMigrateCmd() *cobra.Command` — Task's own `root.go` registration is the only consumer.

- [ ] **Step 1: Write the failing tests**

Create `internal/cli/migrate_test.go`:

```go
package cli

import (
	"bytes"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/keyservice/local"
	"github.com/ducduyn31/git-vault/internal/keyservice/passphrase"
)

// setupTrackedEncryptedFile writes .git-vault.yaml directly (not via
// runInstall — see this file's package-level test comment in
// status_test.go for why), tracks "secret.yaml", writes and git-adds it,
// then encrypts it under the given provider. Returns the plaintext it
// started from.
func setupTrackedEncryptedFile(t *testing.T, provider string) string {
	t.Helper()
	require.NoError(t, config.Save(config.DefaultFileName, config.Config{Provider: provider}))

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

func TestMigrateCmd_LocalToPassphrase_RoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	original := setupTrackedEncryptedFile(t, local.Name)

	t.Setenv(passphrase.EnvVar, "correct horse battery staple")

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{"migrate", "--provider=" + passphrase.Name})
	require.NoError(t, cmd.Execute())
	require.Contains(t, out.String(), "Migrated 1 file")

	cfg, err := config.Load(config.DefaultFileName)
	require.NoError(t, err)
	require.Equal(t, passphrase.Name, cfg.Provider)

	// Prove it actually opens under the NEW provider, not just that the
	// command exited 0.
	decryptCmd := NewRootCmd()
	decryptCmd.SetOut(&bytes.Buffer{})
	decryptCmd.SetArgs([]string{"decrypt", "secret.yaml"})
	require.NoError(t, decryptCmd.Execute())

	opened, err := os.ReadFile("secret.yaml")
	require.NoError(t, err)
	require.Equal(t, original, string(opened))
}

func TestMigrateCmd_SameProviderFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	setupTrackedEncryptedFile(t, local.Name)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"migrate", "--provider=" + local.Name})

	err := cmd.Execute()
	require.ErrorContains(t, err, "already using provider")

	cfg, err := config.Load(config.DefaultFileName)
	require.NoError(t, err)
	require.Equal(t, local.Name, cfg.Provider)
}

func TestMigrateCmd_MissingProviderFlagFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	setupTrackedEncryptedFile(t, local.Name)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"migrate"})

	err := cmd.Execute()
	require.ErrorContains(t, err, "--provider is required")
}

func TestMigrateCmd_UnknownTargetProviderFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	setupTrackedEncryptedFile(t, local.Name)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"migrate", "--provider=bogus"})

	err := cmd.Execute()
	require.ErrorContains(t, err, `unknown provider "bogus"`)

	cfg, err := config.Load(config.DefaultFileName)
	require.NoError(t, err)
	require.Equal(t, local.Name, cfg.Provider)
}

func TestMigrateCmd_PassphraseTarget_MissingEnvVarFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(passphrase.EnvVar, "")
	chdirTemp(t)
	setupTrackedEncryptedFile(t, local.Name)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"migrate", "--provider=" + passphrase.Name})

	err := cmd.Execute()
	require.ErrorContains(t, err, passphrase.EnvVar)

	cfg, err := config.Load(config.DefaultFileName)
	require.NoError(t, err)
	require.Equal(t, local.Name, cfg.Provider, "config must not change when migrate fails fast")

	sealed, err := os.ReadFile("secret.yaml")
	require.NoError(t, err)
	require.Contains(t, string(sealed), "ENC[", "file must stay sealed under the old provider when migrate fails fast")
}

func TestMigrateCmd_NoTrackedFiles_UpdatesConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(passphrase.EnvVar, "correct horse battery staple")
	chdirTemp(t)
	require.NoError(t, config.Save(config.DefaultFileName, config.Config{Provider: local.Name}))

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{"migrate", "--provider=" + passphrase.Name})
	require.NoError(t, cmd.Execute())
	require.Contains(t, out.String(), "Migrated 0 file")

	cfg, err := config.Load(config.DefaultFileName)
	require.NoError(t, err)
	require.Equal(t, passphrase.Name, cfg.Provider)
}

func TestMigrateCmd_MissingConfigFails(t *testing.T) {
	chdirTemp(t)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"migrate", "--provider=" + passphrase.Name})

	err := cmd.Execute()
	require.ErrorContains(t, err, "git vault install")
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/cli/... -run TestMigrateCmd -v`
Expected: FAIL — build error, `unknown command "migrate"` at execute time (cobra has no `migrate` subcommand registered yet).

- [ ] **Step 3: Implement `migrate.go`**

Create `internal/cli/migrate.go`:

```go
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/gitattr"
	"github.com/ducduyn31/git-vault/internal/keyservice/passphrase"
)

// newMigrateCmd re-seals every tracked file from the repo's current
// provider to a different target provider, then updates .git-vault.yaml.
// Same-provider "rotation" is rejected rather than silently no-op'd: both
// existing providers (local, passphrase) have exactly one key source, so
// there is no old/new key pair to rotate between within one provider — see
// docs/superpowers/specs/2026-07-11-migrate-provider-design.md.
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

			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			if target == cfg.Provider {
				return fmt.Errorf("git vault migrate: already using provider %q; in-place key rotation isn't supported (each provider has a single key source) — pick a different --provider", target)
			}

			if target == passphrase.Name && os.Getenv(passphrase.EnvVar) == "" {
				return fmt.Errorf("git vault migrate: %s not set", passphrase.EnvVar)
			}

			oldVault, _, err := vaultForProvider(cfg.Provider)
			if err != nil {
				return fmt.Errorf("git vault migrate: %w", err)
			}
			newVault, newRecipients, err := vaultForProvider(target)
			if err != nil {
				return fmt.Errorf("git vault migrate: %w", err)
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

			if err := config.Save(config.DefaultFileName, config.Config{Provider: target}); err != nil {
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
	cmd.Flags().String("provider", "", "target key provider to migrate to (local, passphrase)")
	return cmd
}
```

- [ ] **Step 4: Register the command in `root.go`**

In `internal/cli/root.go`, add `newMigrateCmd()` to the `root.AddCommand(...)` list (after `newInstallCmd()`, next to the other real commands):

```go
	root.AddCommand(
		newLoginCmd(),
		newTrackCmd(),
		newInstallCmd(),
		newMigrateCmd(),
		newEncryptCmd(),
		newDecryptCmd(),
		newCleanCmd(),
		newSmudgeCmd(),
		newStatusCmd(),
		newVersionCmd(),
	)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/cli/... -run TestMigrateCmd -v`
Expected: PASS for all seven new tests.

- [ ] **Step 6: Full regression check**

Run: `go build ./... && go vet ./... && gofmt -l . && go test ./...`
Expected: no output from `gofmt -l .`; all tests PASS across the whole module, including every pre-existing test.

- [ ] **Step 7: Commit**

```bash
git add internal/cli/migrate.go internal/cli/migrate_test.go internal/cli/root.go
git commit -m "feat: add git vault migrate to re-seal tracked files under a new provider"
```

---

## Final Verification

- [ ] Run `go build ./... && go vet ./... && gofmt -l . && go test ./...` one more time from the repo root.
- [ ] Manually sanity-check `local` → `passphrase` end to end in a scratch directory:
  ```bash
  rm -rf /tmp/gv-migrate-check && mkdir /tmp/gv-migrate-check && cd /tmp/gv-migrate-check
  git init
  go run github.com/ducduyn31/git-vault/cmd/git-vault install
  go run github.com/ducduyn31/git-vault/cmd/git-vault track "secret.yaml"
  echo "password: hunter2" > secret.yaml
  git add secret.yaml
  go run github.com/ducduyn31/git-vault/cmd/git-vault encrypt secret.yaml
  cat secret.yaml   # expect: password: ENC[...]

  export GIT_VAULT_PASSPHRASE="correct horse battery staple"
  go run github.com/ducduyn31/git-vault/cmd/git-vault migrate --provider=passphrase
  cat .git-vault.yaml   # expect: provider: passphrase
  go run github.com/ducduyn31/git-vault/cmd/git-vault decrypt secret.yaml
  cat secret.yaml   # expect: password: hunter2
  ```
