# CLI: `migrate` — re-seal tracked files under a different provider

Date: 2026-07-11
Status: approved

## Purpose

`2026-07-11-provider-selection-design.md` explicitly left "rotating or
migrating existing ciphertext when the provider changes" as follow-up work:
switching `.git-vault.yaml`'s provider today just overwrites the file,
leaving existing ciphertext undecryptable under the new provider. This spec
builds that follow-up: a `git vault migrate --provider=<name>` command that
decrypts every tracked file under the *current* provider and re-seals it
under the *target* provider, then updates `.git-vault.yaml`.

## Non-goals

- **In-place key rotation within the same provider.** Both existing
  providers have exactly one key source: `local` persists one age identity
  at a fixed path (`internal/keyservice/local/local.go`'s `identity()`),
  and `passphrase` reads one shared secret from `GIT_VAULT_PASSPHRASE` for
  both `Encrypt` and `Decrypt`. Neither can produce "the old key" and "a
  new key" at the same time, so `migrate --provider=local` while already on
  `local` (or `passphrase`-to-`passphrase`) cannot do real work — it would
  silently decrypt and re-encrypt with the *identical* key and report
  success. Rather than allow that no-op, `migrate` rejects a target equal
  to the current provider with an explicit error. Generating a second
  identity/passphrase side-by-side so the same provider can rotate its own
  key material is real, separate follow-up work, not built here.
- **Auto-committing the result.** `migrate` only touches the working tree
  (matching `encrypt`/`decrypt`'s existing in-place precedent) and prints
  what to do next. It never runs `git add`/`git commit` itself — that's a
  shared-state action and stays the user's call.
- A third provider, or any change to `internal/keyservice`/`internal/vault`
  themselves. Same boundary as the provider-selection spec.

## Architecture

New file `internal/cli/migrate.go`, alongside a `newMigrateCmd()` wired
into `root.go`:

```go
func newMigrateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Re-seal all tracked files under a different key provider",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := cmd.Flags().GetString("provider")
			...
		},
	}
	cmd.Flags().String("provider", "", "target key provider to migrate to (local, passphrase)")
	return cmd
}
```

Flow, in order (each step fails fast before the next runs — no file is
touched until every precondition holds, and `.git-vault.yaml` isn't written
until every file has been re-sealed):

1. `--provider` must be set (empty string is rejected) and must differ from
   `loadConfig()`'s current `cfg.Provider` — this is the same-provider
   non-goal check above.
2. `target == passphrase.Name` gets the same eager
   `os.Getenv(passphrase.EnvVar) != ""` check `install` already does
   (`passphrase.Provider` has no eager step of its own — see the
   provider-selection spec), so a missing passphrase fails before any file
   is opened.
3. Build both vaults via the existing `vaultForProvider` — `oldVault` for
   `cfg.Provider` (to decrypt) and `newVault, newRecipients` for `target`
   (to re-encrypt). This also catches an unknown `target` name via
   `vaultForProvider`'s existing `default` case.
4. Enumerate tracked files exactly like `status.go` does:
   `gitattr.Tracked(".gitattributes")` guarded for empty (skip
   `trackedFiles` entirely if there are no patterns — same guard `status.go`
   uses, since `git ls-files --` with zero pathspecs is not the same as "no
   files"), then `trackedFiles(patterns)`.
5. For each file: `oldVault.Open(path)` then `newVault.Seal(path,
   newRecipients)`. Both are the same in-place `Vault` methods `encrypt`/
   `decrypt` already use. `Open` is a no-op passthrough on already-plaintext
   content (working-tree files are normally plaintext post-smudge) and
   `Seal`'s "already sealed, pass through" check is purely structural, not
   recipient-specific, so this correctly re-seals under the new recipients
   regardless of whether the working-tree copy happened to be plaintext or
   ciphertext going in.
6. `config.Save(config.DefaultFileName, config.Config{Provider: target})` —
   same shape `install` writes; `IssuerURL`/`ClientID` aren't preserved,
   matching `install`'s existing behavior of always writing a fresh
   `Config`.
7. Print a summary naming the file count and provider change, plus an
   explicit note that the committed ciphertext is still under the old
   provider until the user commits — `git add -A && git commit` finishes
   the migration.

No rollback on a per-file error partway through the loop — a file that
fails to open/seal stops the command immediately and reports which file,
leaving prior files in the loop already migrated. This mirrors the
project's existing lack of transactional guarantees elsewhere (`install`,
`encrypt`) rather than adding new machinery for it.

## Error handling

- `--provider` missing: explicit error, no config or vault work attempted.
- `--provider` equal to current: explicit error naming the non-goal reason.
- Unknown `--provider` value: `vaultForProvider`'s existing error, unchanged.
- `--provider=passphrase` with `GIT_VAULT_PASSPHRASE` unset: explicit error,
  same message shape as `install`.
- Missing `.git-vault.yaml`: `loadConfig`'s existing "run `git vault
  install` first" error, unchanged.
- A file that fails to open (bad old key, tampered MAC) or seal: wrapped
  error naming the file and which provider it failed under.

## Testing

New `internal/cli/migrate_test.go`, following the existing `chdirTemp`/
`config.Save`-direct setup pattern `status_test.go` uses (not `runInstall`,
since `install` also sets `filter.git-vault.*` git config pointing at a
real `git-vault` binary that isn't built under `go test`, and `git add`
would try to invoke it):

- `local` → `passphrase` round trip: track + encrypt a file under `local`,
  migrate to `passphrase`, then `decrypt` (which reads the now-updated
  config) succeeds and returns the original plaintext — proving the file
  actually opens under the *new* provider, not just that the command ran.
- Target equals current provider fails, config untouched.
- Missing `--provider` fails.
- Unknown `--provider` value fails, config untouched.
- `--provider=passphrase` with the env var unset fails, config and tracked
  file untouched (fail-fast, nothing partially migrated).
- No tracked files: still updates `.git-vault.yaml`, reports zero files.
- Missing `.git-vault.yaml` fails with the same install hint as other
  commands.
