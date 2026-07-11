# `uninstall` Command Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish `git vault uninstall` per `docs/superpowers/specs/2026-07-11-uninstall-design.md` — add `--purge-attrs`, gate `--purge-keys` behind a confirmation prompt (`--force` to skip), and warn when unregistering the filter leaves tracked files as unprotected plaintext.

**Architecture:** A prior session already scaffolded `internal/cli/uninstall.go` (base unset + `--purge-config` + unconditional `--purge-keys`) and `internal/cli/uninstall_test.go`. This plan extends both in place: add `gitattr.Untrack` for `--purge-attrs`, add a `trackedFileStates()` helper (reused from `status.go`'s enumeration pattern) to detect sealed vs. plaintext tracked files, and reorder `RunE` so detection and confirmation both happen before any mutation.

**Tech Stack:** Go, cobra, testify/require. No new dependencies.

## Global Constraints

- Flags are independent booleans (`--global`, `--purge-config`, `--purge-attrs`, `--purge-keys`, `--force`) — no `--level` enum.
- Detection (which tracked files are sealed vs. plaintext) must run before any step that could delete `.git-vault.yaml` or `.gitattributes`, regardless of which flags are combined in one invocation.
- `--purge-keys` always prompts (via `cmd.InOrStdin()`/`cmd.OutOrStdout()`, never raw `os.Stdin`, so tests can drive it with `cmd.SetIn`) unless `--force` is passed. Declining returns a non-nil error and the command must not have unset git config or deleted anything.
- `uninstall` never touches `.gitignore` or the git index — only git config, `.git-vault.yaml`, `.gitattributes`, and this machine's local key/session files under `~/.cache/git-vault`.
- `git config --unset` exit code 5 ("key not set") is success, not an error — uninstall must stay idempotent.

---

### Task 1: `gitattr.Untrack`

**Files:**
- Modify: `internal/gitattr/gitattr.go`
- Test: `internal/gitattr/gitattr_test.go`

**Interfaces:**
- Produces: `Untrack(path string) error` — removes every git-vault attribute line from the `.gitattributes` file at `path`, leaving other lines untouched; no-op if the file doesn't exist or has no git-vault lines.

- [ ] **Step 1: Write the failing tests**

Append to `internal/gitattr/gitattr_test.go`:

```go
func TestUntrack_RemovesGitVaultLinesOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".gitattributes")
	content := "*.bin binary\n" +
		"secrets/*.yaml filter=git-vault diff=git-vault -text\n" +
		"*.lfs filter=lfs diff=lfs merge=lfs -text\n" +
		"config/*.env filter=git-vault diff=git-vault -text\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	require.NoError(t, Untrack(path))

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "*.bin binary\n*.lfs filter=lfs diff=lfs merge=lfs -text\n", string(got))
}

func TestUntrack_NoopWhenNothingTracked(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".gitattributes")
	require.NoError(t, os.WriteFile(path, []byte("*.bin binary\n"), 0o644))

	require.NoError(t, Untrack(path))

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "*.bin binary\n", string(got))
}

func TestUntrack_MissingFileIsNoop(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".gitattributes")

	require.NoError(t, Untrack(path))

	_, err := os.Stat(path)
	require.True(t, os.IsNotExist(err))
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/gitattr/... -run TestUntrack -v`
Expected: FAIL — `undefined: Untrack`

- [ ] **Step 3: Implement `Untrack`, refactoring `Tracked` to share the line-matching logic**

Replace the whole `Tracked` function in `internal/gitattr/gitattr.go` with:

```go
// isGitVaultLine reports whether line is a git-vault filter attribute line
// (as written by Track / attrLine), regardless of which pattern it names.
func isGitVaultLine(line string) bool {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return false
	}
	for _, f := range fields[1:] {
		if f == "filter=git-vault" {
			return true
		}
	}
	return false
}

// Tracked returns the patterns tracked by git-vault's filter in the
// .gitattributes file at path. It returns an empty slice if path doesn't
// exist.
func Tracked(path string) ([]string, error) {
	lines, err := readLines(path)
	if err != nil {
		return nil, err
	}

	var patterns []string
	for _, line := range lines {
		if isGitVaultLine(line) {
			patterns = append(patterns, strings.Fields(line)[0])
		}
	}
	return patterns, nil
}

// Untrack removes every git-vault attribute line from the .gitattributes
// file at path, leaving any other lines (other filters, comments) untouched.
// It is a no-op if path doesn't exist or has no git-vault lines.
func Untrack(path string) error {
	lines, err := readLines(path)
	if err != nil {
		return err
	}

	var kept []string
	for _, line := range lines {
		if !isGitVaultLine(line) {
			kept = append(kept, line)
		}
	}
	if len(kept) == len(lines) {
		return nil
	}
	return writeLines(path, kept)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/gitattr/... -v`
Expected: PASS (all tests in the package, including the pre-existing `Track`/`Tracked` ones — the refactor must not change their behavior)

- [ ] **Step 5: Commit**

```bash
git add internal/gitattr/gitattr.go internal/gitattr/gitattr_test.go
git commit -m "feat(gitattr): add Untrack to strip git-vault attribute lines"
```

---

### Task 2: `--purge-attrs` flag

**Files:**
- Modify: `internal/cli/uninstall.go`
- Modify: `internal/cli/uninstall_test.go`

**Interfaces:**
- Consumes: `gitattr.Untrack(path string) error` (Task 1).
- Produces: the `uninstall` command's `--purge-attrs` bool flag, wired to call `gitattr.Untrack(".gitattributes")`.

- [ ] **Step 1: Write the failing test**

Append to `internal/cli/uninstall_test.go`:

```go
func TestUninstallCmd_PurgeAttrs_StripsGitVaultLinesOnly(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	runInstall(t)
	require.NoError(t, os.WriteFile(".gitattributes", []byte("*.bin binary\n"), 0o644))
	require.NoError(t, gitattr.Track(".gitattributes", "secret.yaml"))

	runUninstallWithArgs(t, "--purge-attrs")

	got, err := os.ReadFile(".gitattributes")
	require.NoError(t, err)
	require.Equal(t, "*.bin binary\n", string(got))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cli/... -run TestUninstallCmd_PurgeAttrs -v`
Expected: FAIL — `unknown flag: --purge-attrs`

- [ ] **Step 3: Add the flag and wire it up**

In `internal/cli/uninstall.go`, add the import and flag, and one block in `RunE`.

Add to the import block:

```go
	"github.com/ducduyn31/git-vault/internal/gitattr"
```

Add a new flag read right after the existing `purgeKeys` read:

```go
			purgeAttrs, err := cmd.Flags().GetBool("purge-attrs")
			if err != nil {
				return err
			}
```

Add a new block right after the existing `if purgeKeys { ... }` block:

```go
			if purgeAttrs {
				if err := gitattr.Untrack(".gitattributes"); err != nil {
					return fmt.Errorf("git vault uninstall: %w", err)
				}
			}
```

Register the flag alongside the others:

```go
	cmd.Flags().Bool("purge-attrs", false, "also remove git-vault's filter lines from .gitattributes")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/cli/... -run TestUninstallCmd_PurgeAttrs -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/cli/uninstall.go internal/cli/uninstall_test.go
git commit -m "feat(uninstall): add --purge-attrs flag"
```

---

### Task 3: detect tracked file state + always-on plaintext warning

**Files:**
- Modify: `internal/cli/uninstall.go`
- Modify: `internal/cli/uninstall_test.go`

**Interfaces:**
- Consumes: `gitattr.Tracked(path string) ([]string, error)`, `trackedFiles(patterns []string) ([]string, error)` (both already defined, `trackedFiles` in `internal/cli/status.go`), `vault.IsSealed(path string) (bool, error)`.
- Produces: `trackedFileStates() (sealed, plaintext []string, err error)` in `internal/cli/uninstall.go` — later tasks (Task 4) consume both return slices.

- [ ] **Step 1: Write the failing tests**

Append to `internal/cli/uninstall_test.go`:

```go
// trackPlaintextFile writes .git-vault.yaml directly, tracks "secret.yaml"
// and git-adds it as plaintext (no encrypt), so tests can exercise
// uninstall's plaintext-detection path without a real filter driver.
func trackPlaintextFile(t *testing.T, provider string) {
	t.Helper()
	require.NoError(t, config.Save(config.DefaultFileName, config.Config{Provider: provider}))
	require.NoError(t, gitattr.Track(".gitattributes", "secret.yaml"))
	require.NoError(t, os.WriteFile("secret.yaml", []byte("password: hunter2\n"), 0o644))
	require.NoError(t, exec.Command("git", "add", "secret.yaml").Run())
}

func TestUninstallCmd_WarnsAboutPlaintextTrackedFiles(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	trackPlaintextFile(t, local.Name)

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{"uninstall"})
	require.NoError(t, cmd.Execute())

	require.Contains(t, out.String(), "secret.yaml")
	require.Contains(t, out.String(), "Warning")
}

func TestUninstallCmd_NoWarningWhenNothingTracked(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	runInstall(t)

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{"uninstall"})
	require.NoError(t, cmd.Execute())

	require.NotContains(t, out.String(), "Warning")
}

func TestUninstallCmd_NoWarningWhenTrackedFileIsSealed(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	setupTrackedEncryptedFile(t, local.Name)

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{"uninstall"})
	require.NoError(t, cmd.Execute())

	require.NotContains(t, out.String(), "Warning")
}

func TestUninstallCmd_PurgeAttrs_StillWarnsAboutPlaintextFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	trackPlaintextFile(t, local.Name)

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{"uninstall", "--purge-attrs"})
	require.NoError(t, cmd.Execute())

	require.Contains(t, out.String(), "secret.yaml")
	require.Contains(t, out.String(), "Warning")

	got, err := os.ReadFile(".gitattributes")
	require.NoError(t, err)
	require.NotContains(t, string(got), "filter=git-vault")
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/cli/... -run TestUninstallCmd_WarnsAboutPlaintextTrackedFiles -run TestUninstallCmd_NoWarningWhen -run TestUninstallCmd_PurgeAttrs_StillWarns -v`
Expected: FAIL — the warning text is never printed (no assertion failure on setup; `require.Contains` on `"secret.yaml"`/`"Warning"` fails)

- [ ] **Step 3: Add detection + warning**

In `internal/cli/uninstall.go`, add the import:

```go
	"github.com/ducduyn31/git-vault/internal/vault"
```

Add this function (anywhere at file scope, e.g. after `newUninstallCmd`):

```go
// trackedFileStates enumerates git-vault-tracked files the same way
// status.go does, splitting them into currently-sealed (ciphertext) and
// currently-plaintext. Both empty if nothing is tracked. A file that
// fails vault.IsSealed (e.g. unreadable) is skipped rather than failing
// the whole scan — this feeds a best-effort warning, not a correctness
// check.
func trackedFileStates() (sealed, plaintext []string, err error) {
	patterns, err := gitattr.Tracked(".gitattributes")
	if err != nil {
		return nil, nil, err
	}
	if len(patterns) == 0 {
		return nil, nil, nil
	}

	files, err := trackedFiles(patterns)
	if err != nil {
		return nil, nil, err
	}
	for _, f := range files {
		ok, sealErr := vault.IsSealed(f)
		if sealErr != nil {
			continue
		}
		if ok {
			sealed = append(sealed, f)
		} else {
			plaintext = append(plaintext, f)
		}
	}
	return sealed, plaintext, nil
}
```

In `RunE`, right after the flag-reading block (before the existing `for _, key := range [...] { unsetGitConfig(...) }` loop), add:

```go
			_, plaintext, err := trackedFileStates()
			if err != nil {
				return fmt.Errorf("git vault uninstall: %w", err)
			}
```

Right after the existing "Uninstalled git-vault filter driver ..." `fmt.Fprintf` call (keep that call as-is), add:

```go
			if len(plaintext) > 0 {
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Warning: %d file(s) tracked by git-vault are currently plaintext and no longer protected now that the filter driver is unregistered:\n", len(plaintext)); err != nil {
					return fmt.Errorf("git vault uninstall: %w", err)
				}
				for _, f := range plaintext {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", f); err != nil {
						return fmt.Errorf("git vault uninstall: %w", err)
					}
				}
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), "They will be committed as plaintext if staged before you reinstall (`git vault install`) or handle them manually."); err != nil {
					return fmt.Errorf("git vault uninstall: %w", err)
				}
			}
			return nil
```

(This replaces the old bare `return nil` at the end of `RunE`.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/cli/... -v`
Expected: PASS — full package, since this touches shared `RunE` control flow

- [ ] **Step 5: Commit**

```bash
git add internal/cli/uninstall.go internal/cli/uninstall_test.go
git commit -m "feat(uninstall): warn when unregistering leaves tracked files as plaintext"
```

---

### Task 4: `--purge-keys` confirmation + `--force`, reordered to confirm-before-mutate

**Files:**
- Modify: `internal/cli/uninstall.go`
- Modify: `internal/cli/uninstall_test.go`

**Interfaces:**
- Consumes: `trackedFileStates()` (Task 3), `config.Load(path string) (config.Config, error)`, `local.Name` (`"local"`).
- Produces: `confirmPurgeKeys(out io.Writer, in io.Reader, force bool, sealed []string) (bool, error)` in `internal/cli/uninstall.go`.

This task replaces `RunE`'s body wholesale — the confirm-before-mutate ordering touches nearly every line, so Step 3 gives the complete final function rather than a patch.

- [ ] **Step 1: Write the failing tests**

Append to `internal/cli/uninstall_test.go` (needs a new `"strings"` import — add it to the import block alongside the existing ones):

```go
func TestUninstallCmd_PurgeKeys_DeclineAbortsBeforeAnyMutation(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	runInstall(t)
	provider, err := local.New()
	require.NoError(t, err)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetIn(strings.NewReader("n\n"))
	cmd.SetArgs([]string{"uninstall", "--purge-keys"})
	require.Error(t, cmd.Execute())

	require.Equal(t, "git-vault clean %f", gitConfigGet(t, false, "filter.git-vault.clean"))
	_, statErr := os.Stat(provider.IdentityPath)
	require.NoError(t, statErr, "local identity must survive a declined --purge-keys")
}

func TestUninstallCmd_PurgeKeys_ConfirmYes_Deletes(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	runInstall(t)
	provider, err := local.New()
	require.NoError(t, err)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetIn(strings.NewReader("y\n"))
	cmd.SetArgs([]string{"uninstall", "--purge-keys"})
	require.NoError(t, cmd.Execute())

	_, statErr := os.Stat(provider.IdentityPath)
	require.True(t, os.IsNotExist(statErr))
}

func TestUninstallCmd_PurgeKeys_SpecificWarningNamesSealedFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	setupTrackedEncryptedFile(t, local.Name)

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetIn(strings.NewReader("n\n"))
	cmd.SetArgs([]string{"uninstall", "--purge-keys"})
	require.Error(t, cmd.Execute())

	require.Contains(t, out.String(), "secret.yaml")
	require.Contains(t, out.String(), "permanently unreadable")
}

func TestUninstallCmd_PurgeKeys_GenericWarningWhenNoSealedLocalFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	runInstall(t)

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetIn(strings.NewReader("n\n"))
	cmd.SetArgs([]string{"uninstall", "--purge-keys"})
	require.Error(t, cmd.Execute())

	require.NotContains(t, out.String(), "secret.yaml")
	require.Contains(t, out.String(), "This deletes git-vault's local key material")
}

func TestUninstallCmd_PurgeKeysAndPurgeConfig_StillShowsSpecificWarning(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	setupTrackedEncryptedFile(t, local.Name)

	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetIn(strings.NewReader("y\n"))
	cmd.SetArgs([]string{"uninstall", "--purge-keys", "--purge-config"})
	require.NoError(t, cmd.Execute())

	require.Contains(t, out.String(), "secret.yaml")
	_, err := os.Stat(config.DefaultFileName)
	require.True(t, os.IsNotExist(err))
}
```

Also fix the pre-existing test that will now hang/fail without `--force` (find `TestUninstallCmd_PurgeKeys_RemovesLocalIdentitiesAndSession` in `internal/cli/uninstall_test.go`) — change its call from:

```go
	runUninstallWithArgs(t, "--purge-keys")
```

to:

```go
	runUninstallWithArgs(t, "--purge-keys", "--force")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/cli/... -run TestUninstallCmd_PurgeKeys -v`
Expected: FAIL — `unknown flag: --force` (and the decline/confirm-yes tests fail because nothing prompts yet)

- [ ] **Step 3: Replace `internal/cli/uninstall.go` with the final version**

```go
package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/config"
	"github.com/ducduyn31/git-vault/internal/gitattr"
	"github.com/ducduyn31/git-vault/internal/keyservice/local"
	"github.com/ducduyn31/git-vault/internal/session"
	"github.com/ducduyn31/git-vault/internal/vault"
)

func newUninstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Unregister the git-vault filter driver",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			global, err := cmd.Flags().GetBool("global")
			if err != nil {
				return err
			}
			purgeConfig, err := cmd.Flags().GetBool("purge-config")
			if err != nil {
				return err
			}
			purgeAttrs, err := cmd.Flags().GetBool("purge-attrs")
			if err != nil {
				return err
			}
			purgeKeys, err := cmd.Flags().GetBool("purge-keys")
			if err != nil {
				return err
			}
			force, err := cmd.Flags().GetBool("force")
			if err != nil {
				return err
			}

			sealed, plaintext, err := trackedFileStates()
			if err != nil {
				return fmt.Errorf("git vault uninstall: %w", err)
			}

			if purgeKeys {
				var sealedForPrompt []string
				if cfg, cfgErr := config.Load(config.DefaultFileName); cfgErr == nil && cfg.Provider == local.Name {
					sealedForPrompt = sealed
				}
				confirmed, err := confirmPurgeKeys(cmd.OutOrStdout(), cmd.InOrStdin(), force, sealedForPrompt)
				if err != nil {
					return fmt.Errorf("git vault uninstall: %w", err)
				}
				if !confirmed {
					return fmt.Errorf("git vault uninstall: aborted, --purge-keys declined")
				}
			}

			for _, key := range []string{"filter.git-vault.clean", "filter.git-vault.smudge", "filter.git-vault.required"} {
				if err := unsetGitConfig(global, key); err != nil {
					return fmt.Errorf("git vault uninstall: %w", err)
				}
			}

			if purgeKeys {
				if err := purgeLocalKeys(); err != nil {
					return fmt.Errorf("git vault uninstall: %w", err)
				}
			}

			if purgeAttrs {
				if err := gitattr.Untrack(".gitattributes"); err != nil {
					return fmt.Errorf("git vault uninstall: %w", err)
				}
			}

			if purgeConfig {
				if err := removeIfExists(config.DefaultFileName); err != nil {
					return fmt.Errorf("git vault uninstall: %w", err)
				}
			}

			scope := "repo"
			if global {
				scope = "global"
			}
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Uninstalled git-vault filter driver (%s scope).\n", scope); err != nil {
				return fmt.Errorf("git vault uninstall: %w", err)
			}

			if len(plaintext) > 0 {
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Warning: %d file(s) tracked by git-vault are currently plaintext and no longer protected now that the filter driver is unregistered:\n", len(plaintext)); err != nil {
					return fmt.Errorf("git vault uninstall: %w", err)
				}
				for _, f := range plaintext {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", f); err != nil {
						return fmt.Errorf("git vault uninstall: %w", err)
					}
				}
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), "They will be committed as plaintext if staged before you reinstall (`git vault install`) or handle them manually."); err != nil {
					return fmt.Errorf("git vault uninstall: %w", err)
				}
			}
			return nil
		},
	}
	cmd.Flags().Bool("global", false, "unregister the filter driver from the user's global git config")
	cmd.Flags().Bool("purge-config", false, "also remove "+config.DefaultFileName)
	cmd.Flags().Bool("purge-attrs", false, "also remove git-vault's filter lines from .gitattributes")
	cmd.Flags().Bool("purge-keys", false, "also delete this machine's local key material and cached session (irreversible: encrypted files become permanently unreadable unless the key is backed up elsewhere)")
	cmd.Flags().Bool("force", false, "skip the --purge-keys confirmation prompt")
	return cmd
}

// confirmPurgeKeys prompts on out/in unless force is set, naming sealed
// (files currently encrypted under the local provider) when known, or a
// generic irreversibility warning otherwise. Returns whether to proceed.
func confirmPurgeKeys(out io.Writer, in io.Reader, force bool, sealed []string) (bool, error) {
	if force {
		return true, nil
	}

	if len(sealed) > 0 {
		if _, err := fmt.Fprintf(out, "The following %d file(s) appear to be encrypted with the local key about to be deleted:\n", len(sealed)); err != nil {
			return false, err
		}
		for _, f := range sealed {
			if _, err := fmt.Fprintf(out, "  %s\n", f); err != nil {
				return false, err
			}
		}
		if _, err := fmt.Fprintln(out, "They will become permanently unreadable unless you have a backup of the key."); err != nil {
			return false, err
		}
	} else {
		if _, err := fmt.Fprintln(out, "This deletes git-vault's local key material and cached session for this machine."); err != nil {
			return false, err
		}
	}
	if _, err := fmt.Fprint(out, "This is irreversible. Continue? [y/N] "); err != nil {
		return false, err
	}

	line, _ := bufio.NewReader(in).ReadString('\n')
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}

// trackedFileStates enumerates git-vault-tracked files the same way
// status.go does, splitting them into currently-sealed (ciphertext) and
// currently-plaintext. Both empty if nothing is tracked. A file that
// fails vault.IsSealed (e.g. unreadable) is skipped rather than failing
// the whole scan — this feeds a best-effort warning, not a correctness
// check.
func trackedFileStates() (sealed, plaintext []string, err error) {
	patterns, err := gitattr.Tracked(".gitattributes")
	if err != nil {
		return nil, nil, err
	}
	if len(patterns) == 0 {
		return nil, nil, nil
	}

	files, err := trackedFiles(patterns)
	if err != nil {
		return nil, nil, err
	}
	for _, f := range files {
		ok, sealErr := vault.IsSealed(f)
		if sealErr != nil {
			continue
		}
		if ok {
			sealed = append(sealed, f)
		} else {
			plaintext = append(plaintext, f)
		}
	}
	return sealed, plaintext, nil
}

// unsetGitConfig removes key from git config, treating "key not set" (git's
// exit code 5) as success so uninstall stays idempotent.
func unsetGitConfig(global bool, key string) error {
	args := []string{"config"}
	if global {
		args = append(args, "--global")
	}
	args = append(args, "--unset", key)

	out, err := exec.Command("git", args...).CombinedOutput()
	if err == nil {
		return nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 5 {
		return nil
	}
	return fmt.Errorf("git %s: %w: %s", key, err, out)
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	return nil
}

// purgeLocalKeys deletes this machine's local-provider identities (see
// internal/keyservice/local) and cached session, honoring
// local.IdentityPathEnvVar the same way the provider itself does.
func purgeLocalKeys() error {
	provider, err := local.New()
	if err != nil {
		return err
	}
	if err := removeIfExists(provider.IdentityPath); err != nil {
		return err
	}

	sessionPath, err := session.DefaultPath()
	if err != nil {
		return err
	}
	return removeIfExists(sessionPath)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/cli/... -v`
Expected: PASS — full package (this task touches shared control flow used by every existing uninstall test)

- [ ] **Step 5: Commit**

```bash
git add internal/cli/uninstall.go internal/cli/uninstall_test.go
git commit -m "feat(uninstall): confirm before --purge-keys, add --force"
```

---

### Task 5: README + final verification

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update the uninstall paragraph**

In `README.md`, replace the existing uninstall paragraph:

```markdown
`git vault uninstall` reverses `install`, unregistering the filter driver
(add `--global` to match an `install --global`). It leaves `.git-vault.yaml`
and `.gitattributes` untouched by default; add `--purge-config` to remove
`.git-vault.yaml` too, or `--purge-keys` to also delete this machine's local
key material and cached session — irreversible, since files only that key
can open become permanently unreadable.
```

with:

```markdown
`git vault uninstall` reverses `install`, unregistering the filter driver
(add `--global` to match an `install --global`). It leaves `.git-vault.yaml`
and `.gitattributes` untouched by default; add `--purge-config` to remove
`.git-vault.yaml`, `--purge-attrs` to strip git-vault's lines from
`.gitattributes`, or `--purge-keys` to also delete this machine's local key
material and cached session. `--purge-keys` prompts for confirmation first
(skip it with `--force`), since deleting the key makes anything only it can
decrypt permanently unreadable. Unregistering the filter driver also makes
`.gitattributes`' filter lines inert, so `uninstall` warns if any tracked
file is currently plaintext in your working tree — commit it before
reinstalling, or it'll go into history unencrypted.
```

- [ ] **Step 2: Run the full test suite and vet**

Run: `go vet ./... && go test ./...`
Expected: all packages `ok`, no vet failures

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: document uninstall's --purge-attrs, --force, and plaintext warning"
```
