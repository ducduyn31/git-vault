# CLI: wiring encrypt/decrypt/clean/smudge/install to the real Vault

Date: 2026-07-11
Status: approved

## Purpose

`2026-07-11-vault-sops-integration-design.md` built a real `internal/vault`
(`Seal`/`Open`/`SealStream`/`OpenStream`) and a real `local` key provider,
but explicitly deferred wiring any of that into the CLI. Today
`git-vault encrypt|decrypt|clean|smudge|install` still just return
`"not implemented in scaffold"`. This spec wires those five subcommands to
the real pipeline (`CLI → vault → keyservice → local provider`) — the
first point where `git-vault` actually encrypts and decrypts a file for a
real user.

## Non-goals

- Team key sharing / a repo-tracked recipients list. `local` is
  single-machine only (per the prior spec); this pass always seals to
  *this machine's own* local recipient, resolved live via
  `local.New().Recipient()`. No new field is added to `.git-vault.yaml`,
  and no "add a recipient" command is introduced. Multi-recipient/team
  support is future work for a real (non-`local`) provider.
- A `diff.git-vault.textconv` driver. `install` only sets the
  clean/smudge filter config; making `git diff` render plaintext for
  vault-tracked files is a separate, later improvement.
- The `login`/`status` stub commands — untouched by this pass.
- Any change to `.gitattributes` handling (`internal/gitattr`, already
  real, already wired to `track`).

## Architecture

A new unexported helper in `internal/cli` builds the pipeline every
command needs:

```go
// internal/cli/vault.go
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

`encrypt`, `decrypt`, `clean`, and `smudge` all call this instead of each
repeating the registry/server/provider wiring. `install` calls
`local.New()`/`.Recipient()` directly — it needs the recipient to print,
but not a `Vault`.

## install

Real implementation:

1. `local.New()` then `.Recipient()` — generates and persists the local
   identity if one doesn't already exist (eager, not lazy: the user sees
   their recipient right after running `install`, rather than the first
   time it's silently generated mid-`git add`).
2. Shell out to `git config` (via `os/exec`, no new dependency — git
   itself is already a hard runtime requirement of a git filter driver)
   to set, scoped by the existing `--global` flag
   (`git config` vs `git config --global`):
   - `filter.git-vault.clean = "git-vault clean %f"`
   - `filter.git-vault.smudge = "git-vault smudge %f"`
   - `filter.git-vault.required = true` — fail-closed, per
     `2026-07-10-git-vault-ux-safety-design.md`.
3. Print the recipient and scope (`repo` or `global`) to stdout.

Re-running `install` is idempotent — `git config` overwrites existing
values rather than erroring, and `local.New().Recipient()` reuses the
persisted identity instead of generating a new one.

## encrypt / decrypt

Thin wrappers: build the vault via `newLocalVault()`, then call the
existing `Vault` methods directly on the given file path — no new
plumbing, `Seal`/`Open` already take exactly this shape:

```go
v, recipients, err := newLocalVault()
...
return v.Seal(args[0], recipients) // encrypt
return v.Open(args[0])             // decrypt
```

## clean / smudge

These are git's filter-driver entry points: git invokes
`git-vault clean <path>` / `git-vault smudge <path>` with file content on
stdin and expects the transformed content on stdout; `<path>` (`%f`) is
supplied for context (format detection), not as a file to open directly.
`Args` changes from `cobra.MaximumNArgs(1)` to `cobra.ExactArgs(1)` — git
always supplies `%f`, and format detection requires it.

```go
v, recipients, err := newLocalVault()
...
format := vault.FormatForPath(args[0])
return v.SealStream(cmd.OutOrStdout(), cmd.InOrStdin(), format, recipients) // clean
return v.OpenStream(cmd.OutOrStdout(), cmd.InOrStdin(), format)             // smudge
```

## Idempotency (modifies internal/vault)

Git can invoke `clean` on content that's already sops-encrypted (e.g. a
merge/rebase re-applying filters), and `smudge` on content that's still
plaintext (e.g. before a file was ever encrypted). Both `SealStream` and
`OpenStream` gain a passthrough check so this doesn't double-encrypt or
hard-error:

- `SealStream`: before building a fresh tree, try
  `store.LoadEncryptedFile(plaintext)`. If it succeeds (the input already
  has valid sops metadata for this format), write the input through to
  `w` unchanged instead of re-sealing.
- `OpenStream`: if `store.LoadEncryptedFile(ciphertext)` fails to find a
  sops metadata block (as opposed to some other decrypt failure, e.g. a
  key-service error or MAC mismatch further down), treat the input as
  already-plaintext and write it through to `w` unchanged instead of
  erroring.

This lives inside `vault`, not duplicated per CLI command, so `encrypt`
and `clean` share one seal-side check, `decrypt` and `smudge` share one
open-side check, and any future caller gets both for free.

## Error handling

Errors propagate through `RunE` → `main.go` prints to stderr and exits 1
(unchanged, already how the CLI works today). Combined with
`filter.git-vault.required = true` (set by `install`), a `clean`/`smudge`
failure aborts the git operation instead of passing plaintext or garbage
through — the fail-closed behavior `2026-07-10-git-vault-ux-safety-design.md`
calls for.

## Testing

- `internal/vault`: two new tests — `SealStream` on already-sealed input
  passes through unchanged; `OpenStream` on already-plaintext input
  passes through unchanged.
- `internal/cli`: round-trip tests for `encrypt`+`decrypt` and for
  `clean`+`smudge` (piping stdin/stdout). Each isolates the local
  identity's cache directory with `t.Setenv("HOME", t.TempDir())` before
  calling `newLocalVault()`, so tests never touch a real machine's
  `~/.cache/git-vault` identity. An `install` test runs inside a `t.TempDir()`
  git repo (`git init`) and asserts the three `git config --get` values
  land correctly, both with and without `--global`.
- Remove `encrypt`, `decrypt`, `clean`, `smudge`, `install` from
  `TestStubCommands_NotImplemented`'s cases in `root_test.go` — only
  `login` and `status` remain stubs after this pass.
