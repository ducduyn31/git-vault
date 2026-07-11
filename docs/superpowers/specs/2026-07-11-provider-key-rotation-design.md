# Passphrase/local provider redesign: interactive entry + key rotation

Date: 2026-07-11
Status: approved

## Purpose

Two follow-ups deferred by earlier specs land here together, because they
share the same root cause:

- `2026-07-11-provider-selection-design.md` and
  `2026-07-11-migrate-provider-design.md` both note that `local` and
  `passphrase` each have exactly one fixed key source — `local` persists one
  age identity at one fixed path, `passphrase` reads one secret from
  `GIT_VAULT_PASSPHRASE` — so neither can hold "an old key" and "a new key"
  at once. `migrate` explicitly rejects a same-provider target for this
  reason; there is no way to rotate a key within a provider today.
- `passphrase`'s only entry point is `GIT_VAULT_PASSPHRASE`: no interactive
  prompt, so using it means exporting a secret into your shell environment
  by hand every time.

Both problems are solved by the same change: move each provider from
"exactly one key" to "an ordered list of keys, newest last" — encrypt always
targets the newest, decrypt matches whichever key actually encrypted the
file. A new `git vault rotate` command generates a new key and re-seals
tracked files under it, while old keys remain valid for anything not yet
re-sealed (including committed history).

## Non-goals

- **Passphrase-encrypting the local identity file at rest.** `local` stays
  the no-login, no-shared-secret provider by design; this pass only removes
  its single-fixed-path limitation.
- **`rotate --provider=X` / cross-provider rotation.** That is `migrate`'s
  job already and is unchanged by this spec.
- **Key-management subcommands** (`list-keys`, `revoke-key`, expiry,
  pruning old keys). `rotate` only ever *adds* a new key. Removing an old
  line from `identities` or `GIT_VAULT_PASSPHRASE` stays a manual edit.
- **Any change to the `keyservice.Provider` interface** (`Name`/`Encrypt`/
  `Decrypt` stay exactly as declared in `internal/keyservice/provider.go`).
  This is entirely internal to the two provider implementations plus one
  new CLI command.
- **Concurrency/locking** on the in-memory secret cache described below.
  Every existing call site (`encrypt`, `decrypt`, `clean`, `smudge`,
  `migrate`, `rotate`) processes files sequentially in one goroutine — see
  the absence of `go func`/goroutines anywhere under
  `internal/vault`/`internal/keyservice`/`internal/cli` today. A mutex is
  added only because `Provider` becomes a pointer receiver with lazily
  initialized state, not because of any real concurrent access.

## `passphrase` provider

`internal/keyservice/passphrase/passphrase.go`:

- **Storage format**: `GIT_VAULT_PASSPHRASE` becomes newline-separated,
  oldest first, newest (current) last. A single-line value — today's
  entire installed base — keeps working unchanged.
- **`Provider` becomes stateful**, a pointer type caching the loaded
  secrets so a command touching many tracked files (or a multi-line env
  var) doesn't reprompt per file:

  ```go
  type Provider struct {
      mu      sync.Mutex
      secrets []string // newest last; loaded lazily on first use
  }
  ```

- **Lookup** (replaces `lookupPassphrase`): if `GIT_VAULT_PASSPHRASE` is
  set, split on `\n`, drop blank lines — no prompt, matching today's
  non-interactive behavior exactly. If unset: check
  `term.IsTerminal(int(os.Stdin.Fd()))`; if not a terminal, fail with the
  same shape of error as today ("set GIT_VAULT_PASSPHRASE"), just extended
  to mention the interactive option; if it is a terminal, prompt once via
  `term.ReadPassword`, cache the single result. Loaded once per `Provider`
  instance (i.e. once per process — every CLI command builds a fresh
  `Provider` per invocation today, so this doesn't change per-process
  behavior, only per-*file* behavior within one process).
- **Prompting goes through a package-level seam, not a direct
  `term.ReadPassword` call**: `term.ReadPassword(fd)` reads via a termios
  ioctl on a real terminal file descriptor — it cannot be pointed at a
  `bytes.Buffer` or any other `io.Reader`, so a test running under `go
  test` (no real tty) cannot exercise the prompt path by injecting a fake
  reader. Both the single-entry lookup prompt and `PromptNewSecret`'s
  double-entry prompt call through an unexported `var promptFn func()
  (string, error)` (default implementation wraps `IsTerminal` +
  `ReadPassword` as above); tests replace `promptFn` with a stub returning
  canned values/errors, the same pattern already used for stubbing other
  non-deterministic dependencies (e.g. swapping `time.Now`).
- **`Encrypt`** builds a `ScryptRecipient` from `secrets[len(secrets)-1]`
  (the newest) — same call as today, just indexed instead of a single
  value.
- **`Decrypt`** builds a `ScryptIdentity` for every entry in `secrets` and
  passes them all to one `age.Decrypt(ar, identities...)` call. Verified
  directly against `filippo.io/age@v1.3.1`: the "must be the only one"
  restriction (`scrypt.go`'s `errors.New("an scrypt recipient must be the
  only one")`) applies only to `ScryptRecipient` on the encrypt side —
  `Decrypt` has no equivalent guard on the identity side, and a call with
  multiple `ScryptIdentity` values trying each in turn until one matches
  works today. Build the identity slice **newest-first** (reverse of
  `secrets`' storage order) purely as a performance choice: scrypt's KDF is
  deliberately slow, and the common case post-rotation is that the newest
  passphrase is the one in use, so trying it first avoids paying that cost
  on every older entry first. `keyID` stays ignored, as today (the
  passphrase provider has never distinguished versions by key-id; a
  `"passphrase:shared"` identifier is issued regardless of how many lines
  back it).
- **New exports for `rotate`** (see below):
  - `NewWithSecret(secret string) Provider` — bypasses the env-var/prompt
    lookup entirely, `secrets` fixed to the one given value. Used to build
    the "new" side of a rotation without touching `GIT_VAULT_PASSPHRASE`
    (which this process cannot rewrite for future shell sessions anyway).
  - `PromptNewSecret(out io.Writer) (string, error)` — always prompts via
    TTY (no env var alternative for this one, since a fresh passphrase is a
    deliberate one-off action), entered twice, fails if the two entries
    don't match or stdin isn't a terminal.

## `local` provider

`internal/keyservice/local/local.go`:

- **File rename**: `identity.txt` → `identities` (no extension — it now
  holds a list, matching the real `age` CLI's own convention for identity
  files: one identity per line, blank lines and `#`-comments ignored,
  parseable by `age.ParseIdentities`).
- **Configurable path**: resolution order becomes
  `GIT_VAULT_LOCAL_IDENTITY_PATH` (new env var, mirroring
  `passphrase.EnvVar`'s naming) if set, else `DefaultIdentityPath()`
  (unchanged default directory, just the new filename).
- **Loading** (`identity()` renamed `identities()`): reads the file via
  `age.ParseIdentities`; if the file doesn't exist, generates a single
  fresh identity and creates it — same first-run behavior as today,
  producing a one-element list.
- **`Recipient()`** returns the **newest** (last) identity's public key —
  what `install` prints and what future `Seal` calls target.
- **`Encrypt(keyID, ...)`** is unchanged: it already just parses whatever
  recipient string it's handed and encrypts to it, independent of which
  identity produced that string or how many others exist.
- **`Decrypt(keyID, ...)`** changes from "parse the one identity, decrypt"
  to: load all stored identities, select the one whose
  `Recipient().String() == keyID` (the file's own sops metadata already
  names exactly which recipient encrypted it — no brute-force trial
  needed, unlike passphrase), decrypt with just that one. Clear error if no
  stored identity matches (e.g. the matching line was manually removed, or
  the file is from a different machine).
- **New export for `rotate`**: `func (p *Provider) Rotate() (recipient
  string, err error)` — generates a fresh `X25519Identity`, appends it to
  the identities file (creating it first via the existing
  load-or-generate path if it doesn't exist yet), and returns its recipient
  string. Persists before returning, not after some later step, so a
  process that dies right after `Rotate()` still leaves the new key
  durably on disk.

## `git vault rotate`

New `internal/cli/rotate.go`, wired into `root.go` alongside `migrate`:

```go
func newRotateCmd() *cobra.Command {
    return &cobra.Command{
        Use:   "rotate",
        Short: "Generate a new key and re-seal all tracked files under it",
        Args:  cobra.NoArgs,
        RunE: func(cmd *cobra.Command, args []string) error {
            cfg, err := loadConfig()
            ...
        },
    }
}
```

No flags: rotate always targets `cfg.Provider` from `.git-vault.yaml` — the
provider name never changes, so (unlike `migrate`) there is no
`config.Save` step.

Flow:

1. `loadConfig()` — same missing-file error as every other command.
2. Enumerate tracked files exactly like `migrate`:
   `gitattr.Tracked(".gitattributes")` guarded for empty, then
   `trackedFiles(patterns)`.
3. Build the vault(s) to re-seal with, branching on `cfg.Provider`:
   - **`local.Name`**: `local.New()` → `provider.Rotate()` (generates and
     durably persists the new identity *before* any file is touched) →
     wrap the same `*local.Provider` instance in one `Registry`/`Server`/
     `Vault`. Because `Decrypt` now matches by exact `keyID` rather than
     trying every identity, this single vault correctly `Open`s files
     sealed under the old identity (its recipient is still in the file)
     and `Seal`s new ciphertext to the newly-returned recipient — no
     separate "old vault"/"new vault" needed for `local`.
   - **`passphrase.Name`**: two vaults, because there is no local file to
     append the new secret to. `oldVault` is the existing
     `vaultForProvider(passphrase.Name)` (env var or single prompt, as
     today/above). `newSecret, err := passphrase.PromptNewSecret(...)`,
     then build `newVault` from `passphrase.NewWithSecret(newSecret)` in
     its own `Registry`/`Server`, with `newRecipients =
     []string{passphrase.Name + ":" + passphrase.KeyID}` (same fixed
     identifier as today — the passphrase provider has never versioned its
     key-id).
   - Any other provider name: same "unknown provider" error
     `vaultForProvider` already returns.
4. For each tracked file: `oldVault.Open(f)` then `newVault.Seal(f,
   newRecipients)` — identical shape to `migrate`'s loop (for `local`,
   `oldVault`/`newVault` are literally the same `*vault.Vault`).
5. Print a summary naming the file count and the follow-up the user still
   owes:
   - `local`: old identity is retained (not deleted) so anything not yet
     re-sealed — including already-committed ciphertext — still decrypts;
     `git add -A && git commit` finishes the migration, same phrasing
     `migrate` already uses.
   - `passphrase`: distribute the new passphrase to the team out-of-band;
     keep `GIT_VAULT_PASSPHRASE` set to the old value *and* the new value
     (old first, new last, one per line) until every teammate has
     re-sealed locally, then the old line can be dropped. Neither summary
     echoes the actual secret value back — the user just typed it, so
     nothing new is revealed by printing it, but there's no reason to add
     a secret to scrollback/logs that isn't already needed there.

No rollback on a per-file error partway through, same rationale `migrate`
already documents (this project's existing lack of transactional
guarantees elsewhere, not new machinery here) — with the one exception
already covered above: `local`'s new identity is persisted *before* the
loop starts specifically so a failure partway through can't strand
already-re-sealed files with no matching private key on disk.

`passphrase`'s failure mode on a mid-loop error is strictly worse than
`local`'s or `migrate`'s, and worth calling out explicitly rather than
leaving implicit: the new secret is never written anywhere by git-vault
(unlike `local`'s identity file) — it exists only in what the user just
typed into the prompt. If the reseal loop dies partway through, the files
already re-sealed under the new secret are only recoverable if the user
remembers (or separately recorded) the passphrase they entered seconds
earlier. This is accepted as a documented trade-off consistent with
`passphrase`'s existing "no local state, distribute out-of-band" design,
not something this spec adds new machinery to guard against.

## Error handling

- Missing `.git-vault.yaml`: `loadConfig`'s existing hint, unchanged.
- Unknown provider name in config: same error `vaultForProvider` returns
  today.
- `passphrase` rotate when stdin isn't a terminal: explicit error from
  `PromptNewSecret` — there is no env var fallback for the new secret,
  since generating one is a deliberate one-off action, not routine
  CI/scripted traffic.
- `passphrase` rotate when the two new-passphrase entries don't match:
  explicit error from `PromptNewSecret`, nothing touched.
- `passphrase`/`local` lookup failures during the reseal loop (bad old
  key, tampered MAC): wrapped error naming the file, same shape `migrate`
  uses today.
- No tracked files: still succeeds — `local` still rotates its identity
  (0 files re-sealed), `passphrase` still prompts and reports 0 files.
  Matches `migrate`'s existing "no tracked files" behavior of still doing
  the provider-level work and reporting zero.

## Testing

- `internal/keyservice/passphrase`: multi-line `GIT_VAULT_PASSPHRASE`
  round-trip (file encrypted under an older line still opens, proving the
  multi-`ScryptIdentity` `age.Decrypt` call — verified directly against
  `filippo.io/age@v1.3.1` to have no "only one identity" restriction on the
  decrypt side, unlike `ScryptRecipient` on encrypt — actually works);
  `Encrypt` always uses the last line; `NewWithSecret` bypasses the env var
  entirely; the prompt path (both single-entry lookup and
  `PromptNewSecret`'s double-entry) exercised by stubbing the package-level
  `promptFn` seam, since `term.ReadPassword` itself needs a real terminal
  fd and can't be driven by a fake `io.Reader` under `go test`; missing env
  var + non-terminal stdin fails with the existing error shape.
- `internal/keyservice/local`: identities file round-trip with 2+ entries
  (older entry still decrypts its own ciphertext); `Recipient()` returns
  the last entry; `Rotate()` appends without disturbing existing entries
  and returns the new recipient; `GIT_VAULT_LOCAL_IDENTITY_PATH` overrides
  the default path; decrypting with a `keyID` matching no stored identity
  fails with a clear error; the renamed file (`identities`, no extension)
  is what gets created on first use.
- `internal/cli`: new `rotate_test.go`, following `migrate_test.go`'s
  `chdirTemp`/`config.Save`-direct setup:
  - `local` rotate: track + encrypt a file, rotate, confirm the file still
    opens (now via the new identity's presence, old identity retained),
    confirm a *second* rotate still works (list keeps growing), confirm
    `.git-vault.yaml` is untouched.
  - `passphrase` rotate: same shape, stubbing the same `promptFn` seam
    `internal/keyservice/passphrase`'s own tests use, so no real terminal
    is needed here either.
  - No tracked files: rotate still succeeds for both providers.
  - Missing `.git-vault.yaml`: same install hint as other commands.
  - Unknown provider in config: fails with the existing error.
