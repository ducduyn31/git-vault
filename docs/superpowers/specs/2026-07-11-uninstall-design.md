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

Unsetting `filter.git-vault.*` also has a side effect worth calling out
up front: git only enforces a filter if it's configured, so once the
config is gone, `.gitattributes`' `filter=git-vault` lines become inert —
git treats them as "filter not configured" and passes content through
unchanged. Any tracked file sitting as plaintext in the working tree
(the normal post-smudge state) is therefore one `git add`/`git commit`
away from landing in git history as plaintext, silently. `uninstall`
can't prevent this without going far beyond config/key cleanup (see the
gitignore non-goal below), so it detects and warns about it instead.

## Non-goals

- **Decrypting tracked files back to plaintext before uninstalling.**
  Working-tree files are already plaintext post-smudge in the common case;
  `uninstall` doesn't touch file contents at all, only tool registration
  and key/config state.
- **Gitignoring or untracking now-unprotected plaintext files.** Adding a
  currently-tracked file to `.gitignore` has no effect — ignore rules only
  apply to untracked paths, so it would not stop `git add`/`git commit -a`
  from picking up the plaintext. Actually neutralizing the risk would mean
  `git rm --cached` (removing the file from the index, a change to the
  staging area) in addition to `.gitignore` — a much bigger action than
  `uninstall`'s otherwise config/key-only blast radius. `uninstall` warns
  about the risk (see "Post-uninstall plaintext warning") rather than
  mutating the index on the user's behalf.
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

1. **Detect state (read-only), always.** Try `loadConfig()` and, if
   `.gitattributes` has any tracked patterns, enumerate tracked files the
   same way `status.go` does (`gitattr.Tracked` + `trackedFiles` +
   `vault.IsSealed` per file), splitting them into currently-sealed and
   currently-plaintext. This must run before any later step deletes
   `.git-vault.yaml` or `.gitattributes`, regardless of which purge flags
   are combined in the same invocation — otherwise a `--purge-keys
   --purge-config` (or `--purge-attrs`) call would find nothing left to
   inspect. Both lists feed later steps: sealed files (when the provider
   is `local`) drive the `--purge-keys` confirmation message; plaintext
   files drive the post-uninstall warning, both described below.
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
7. Print a summary: scope (`repo`/`global`), which purge levels ran, and
   the post-uninstall plaintext warning (below) if step 1 found any
   currently-plaintext tracked files.

## Post-uninstall plaintext warning

If step 1 found any tracked files that are currently plaintext, print
(after the rest of the summary, so it's the last thing the user sees):
"Warning: N file(s) tracked by git-vault are currently plaintext and no
longer protected now that the filter driver is unregistered: file1,
file2, ... They will be committed as plaintext if staged before you
reinstall (`git vault install`) or handle them manually." This fires
regardless of which purge flags were passed, since it's `filter.git-vault.*`
being unset (the one thing every `uninstall` call does) that disables the
filter — not `--purge-attrs` or any other flag.

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
- A plain uninstall (no flags) with a tracked, currently-plaintext file
  prints the post-uninstall plaintext warning naming that file.
- The warning is absent when there are no tracked files, or when every
  tracked file is currently sealed.
- `--purge-attrs` combined with a tracked plaintext file still prints the
  warning (proving step 1 reads `.gitattributes` before step 5 strips it).
