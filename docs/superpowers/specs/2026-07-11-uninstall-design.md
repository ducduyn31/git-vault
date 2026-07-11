# CLI: `uninstall` — reverse `install`, with configurable purge levels

Date: 2026-07-11
Status: approved

## Purpose

`install` (`internal/cli/install.go`) registers git-vault's filter driver
in git config and writes `.git-vault.yaml`. There is no way to undo that
short of manually running `git config --unset` three times and hand-editing
or deleting files. This spec adds `git vault uninstall`, whose base
behavior is the exact inverse of `install`, plus opt-in flags for deeper
levels of cleanup: the repo-tracked config, the `.gitattributes` tracking
lines, and this machine's local key material.

## Non-goals

- **Decrypting tracked files back to plaintext before uninstalling.**
  Working-tree files are already plaintext post-smudge in the common case;
  `uninstall` doesn't touch file contents at all, only tool registration
  and key/config state.
- **A single `--level` enum.** Flags are independent and combinable
  (`--purge-config`, `--purge-attrs`, `--purge-keys`), matching `install`'s
  existing flag style rather than introducing a new "level" concept.
- **Proving a specific ciphertext needs the exact key being deleted.**
  The `--purge-keys` safety check infers risk from "provider is `local` and
  something is currently sealed," not from parsing sops recipient metadata
  per file. See "Purge-keys confirmation" below.
- **Provider-specific cleanup for `passphrase`.** It reads its secret from
  an env var and persists nothing on disk (see
  `internal/keyservice/passphrase/passphrase.go`), so there is nothing for
  `--purge-keys` to delete on that provider's behalf beyond the
  provider-agnostic session cache.

## Architecture

New file `internal/cli/uninstall.go`, a `newUninstallCmd()` wired into
`root.go` next to `newInstallCmd()`:

```go
func newUninstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Unregister the git-vault filter driver",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error { ... },
	}
	cmd.Flags().Bool("global", false, "unregister the filter driver from the user's global git config")
	cmd.Flags().Bool("purge-config", false, "also remove "+config.DefaultFileName)
	cmd.Flags().Bool("purge-attrs", false, "also remove git-vault's filter lines from .gitattributes")
	cmd.Flags().Bool("purge-keys", false, "also delete this machine's local key material and cached session (irreversible)")
	cmd.Flags().Bool("force", false, "skip the --purge-keys confirmation prompt")
	return cmd
}
```

Flow, in order — detection and confirmation both happen before any
mutation, so a decline leaves the repo completely untouched (no git config
unset, no files deleted):

1. **Detect risk (read-only).** If `--purge-keys` is set: try
   `loadConfig()` and, if it succeeds and `cfg.Provider == local.Name`,
   enumerate tracked files the same way `status.go` does
   (`gitattr.Tracked` + `trackedFiles` + `vault.IsSealed` per file) and
   collect which ones are currently sealed. This must run before any later
   step deletes `.git-vault.yaml` or `.gitattributes`, regardless of which
   purge flags are combined in the same invocation — otherwise a
   `--purge-keys --purge-config` call would find no config left to inspect.
2. **Confirm, if `--purge-keys` is set** (see "Purge-keys confirmation"
   below). Declining returns a non-nil error immediately — nothing from
   step 3 onward runs, so scripts see a non-zero exit and the repo is
   exactly as it was before the command ran.
3. **Unset git config**, always: `filter.git-vault.{clean,smudge,required}`
   via a new `unsetGitConfig(global bool, key string) error` (mirrors
   `setGitConfig`, using `git config [--global] --unset <key>`). Git's
   exit code 5 ("key not set") is treated as success, so a repeat uninstall
   or uninstalling something never installed is a no-op, not an error.
4. **Delete keys, if `--purge-keys` was confirmed (or `--force`'d) in step
   2:** `local.New()`'s `Provider.IdentityPath` and `session.DefaultPath()`,
   both via a shared `removeIfExists(path string) error` that treats
   "already gone" as success.
5. **`--purge-attrs`, if set:** new `gitattr.Untrack(path string) error`
   strips every line matching the package's existing `attrLine` format
   (`<pattern> filter=git-vault diff=git-vault -text`) from
   `.gitattributes`, leaving any unrelated lines (other filters, comments)
   untouched. No-op if the file doesn't exist or has no matching lines.
6. **`--purge-config`, if set:** `removeIfExists(config.DefaultFileName)`.
7. Print a summary: scope (`repo`/`global`) and which purge levels ran.

## Purge-keys confirmation

`--purge-keys` always prompts (reads a line from stdin, proceeds only on
`y`/`yes`) unless `--force` is passed. Two message shapes, chosen by what
step 1 found:

- **Specific:** config loaded, provider is `local`, and N tracked files are
  currently sealed → name them: "The following N file(s) appear to be
  encrypted with the local key about to be deleted: ... They will become
  permanently unreadable unless you have a backup of the key. Continue?
  [y/N]".
- **Generic:** config missing/unreadable, provider isn't `local`, or no
  tracked file is currently sealed → "This deletes git-vault's local key
  material and cached session for this machine. This is irreversible.
  Continue? [y/N]".

`--force` skips the prompt in both cases and proceeds directly to deletion
(for scripts/CI, where there's no stdin to read anyway).

## Error handling

- `git config --unset` failing for a reason other than "key not set" (exit
  code 5): wrapped error, remaining purge steps don't run.
- `--purge-keys` prompt declined: command returns an error before git
  config is touched — the repo is left exactly as it was.
- `os.Remove` failing for a reason other than "not exist" (e.g. permission
  denied) on any purged path: wrapped error naming the path.
- No flags at all, nothing installed: succeeds silently (git config unset
  is idempotent), same as running it after a real install.

## Testing

Extend `internal/cli/uninstall_test.go` (already scaffolded from prior
work) to cover:

- Base uninstall unsets repo-local filter config; `--global` unsets global.
- Uninstall with nothing installed is a no-op, no error.
- Default (no purge flags) leaves `.git-vault.yaml` and `.gitattributes`
  untouched.
- `--purge-config` removes `.git-vault.yaml`.
- `--purge-attrs` strips git-vault lines from `.gitattributes`, leaving
  non-git-vault lines in place.
- `--purge-keys --force` removes the local identity file and session
  cache without prompting.
- `--purge-keys` without `--force`, answering "n" on stdin: nothing is
  deleted, command returns an error.
- `--purge-keys` without `--force`, answering "y": deletes as normal.
- The specific-vs-generic warning message: a tracked+encrypted file under
  the `local` provider produces a message naming that file; a passphrase
  provider (or no tracked files) produces the generic message instead.
- Combining `--purge-keys --purge-config` in one call still produces the
  specific warning (proving step 1's config read happens before step 6's
  deletion).
- `--purge-keys` prompt declined: git config is still set afterward (proves
  the decline aborted before step 3, not just before step 4).
