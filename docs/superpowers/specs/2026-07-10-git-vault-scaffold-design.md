# git-vault: project scaffold design

Date: 2026-07-10
Status: approved (scaffold only — no crypto/backend logic implemented yet)

## Purpose

`git-vault` is a Go-based git extension that transparently encrypts secret
files in a repository, using a pluggable key-provider system (not limited
to SSO — SSO is the first provider, others follow the same interface).
This document specs the initial professional project scaffold: repo
layout, tooling, CI, and package boundaries. It does not implement
encryption or any real provider — those are separate follow-up
specs/plans.

## Non-goals (for this scaffold)

- No real key provider implementation (only a stub/mock `Provider`).
- No real sops integration logic beyond wrapper/keyservice package stubs.
- No published releases; goreleaser config exists but is not exercised.

## Git integration model

Modeled directly on git-lfs, which is the established pattern for "git
extension that transforms file content on checkout/commit":

1. **Filter driver, fail-closed.** `git vault install` (or
   `git vault install --global`) registers a git filter driver:
   `filter.git-vault.clean`, `filter.git-vault.smudge`, and critically
   `filter.git-vault.required true`. `required` means if clean/smudge ever
   errors (no session, no provider, sops failure) git aborts the operation
   instead of silently passing raw content through. `--global` installs
   the filter driver in the user's global git config (same pattern as
   `git lfs install --global`), so any repo cloned afterwards is protected
   immediately, with no per-clone re-init step to forget.
2. **Attribute tracking.** `git vault track "<pattern>"` appends a line to
   `.gitattributes`: `<pattern> filter=git-vault diff=git-vault -text`
   (same shape as `git lfs track`). git-vault does not need its own
   pattern-tracking config file — `.gitattributes` is the single source of
   truth, and commands like `status` parse it for `filter=git-vault` lines
   when they need the tracked set.
3. **Explicit mode.** `git vault encrypt/decrypt <file>` performs the same
   seal/open operation outside the filter path, for manual use or
   scripting.
4. **No pre-commit hook.** git-vault does not install a pre-commit hook —
   it would risk clobbering/conflicting with a repo's existing hook setup
   (husky, pre-commit framework, etc.). The fail-closed filter is the
   safety net; `git vault status` is available for a user or their CI to
   wire into their own hook if they want an extra check.

See `2026-07-10-git-vault-ux-safety-design.md` for why these specific
choices (fail-closed, global install, no comment-marker opt-in) were made
— they respond directly to real footguns found in a prior art review.

### Auth is decoupled from the filter path

Git filters run in contexts with no tty and may run concurrently or
non-interactively (e.g. during a parallel checkout). A filter must never
block on an interactive SSO prompt. So:

- `git vault login` performs a provider's interactive flow once (e.g. SSO)
  and caches a short-lived session locally (`~/.cache/git-vault/`).
- `clean`/`smudge`/`encrypt`/`decrypt` only ever *read* the cached session.
  If it's missing or expired, they fail fast with a message telling the
  user to run `git vault login` — they never attempt to trigger a login
  themselves.
- Not every provider needs a session (e.g. a KMS-backed provider might use
  ambient cloud credentials instead) — the session cache is used by
  providers that need it, not a requirement of the `Provider` interface.

## Encryption engine and extensible providers

Rather than reimplementing structured partial-file encryption (only
encrypt the values in a YAML/JSON/ENV file, keep keys/structure readable),
git-vault uses `github.com/getsops/sops/v3` as a library, unmodified.
sops already supports pluggable key backends and, importantly, already has
an extension point designed for exactly this scaffold's goal: the
**keyservice protocol** — sops delegates Encrypt/Decrypt of the data key to
a local or remote gRPC `KeyServiceServer` rather than requiring new key
types to be compiled into sops itself.

git-vault runs its own local `KeyServiceServer` (`internal/keyservice`)
that implements Encrypt/Decrypt by dispatching to a **pluggable
`Provider`** — SSO is the first provider, not the only one. Adding a new
backend later (an internal KMS, HashiCorp Vault via a custom flow,
whatever) means implementing one small `Provider` interface and
registering it — no changes to `internal/vault`, `internal/cli`, or sops
itself. Because this is sops's own real extension mechanism, git-vault
files stay interoperable with stock sops tooling, and a single file can
even mix a git-vault provider key with a native sops key (age/KMS/PGP/
Vault) in the same key group.

## Package layout

```
cmd/git-vault/          main.go — cobra root, wires subcommands
internal/cli/           login, track, install, encrypt, decrypt, clean, smudge, status, version
internal/keyservice/    sops KeyServiceServer implementation + Provider interface + registry; stub provider only for now
internal/session/       local session cache (~/.cache/git-vault): read/write, expiry check — used by providers that need it
internal/vault/         thin wrapper calling sops-as-a-library, configured to use git-vault's local keyservice (Seal/Open, streaming for clean/smudge)
internal/gitattr/       read/write .gitattributes track lines (git-lfs-style)
internal/config/        which provider(s)/keyservice endpoint to use, session settings (not pattern tracking)
```

Each package has one job:
- `internal/keyservice` never knows about git or file formats — it's a
  sops KeyServiceServer plus a `Provider` registry.
- `internal/vault` never knows about providers or SSO — it only knows how
  to call sops with a configured keyservice endpoint.
- `internal/gitattr` never knows about encryption — it only edits
  `.gitattributes` lines.
- `internal/session` never knows about sops or providers — it's a generic
  cache-with-expiry, used by whichever providers need it.

This means each can be tested and reasoned about independently, and a real
provider implementation later only touches `internal/keyservice` (add a
`Provider`) without needing changes to `internal/cli`, `internal/vault`,
`internal/gitattr`, or `internal/session`.

## CLI

cobra-based, subcommands: `login`, `track`, `install`, `encrypt`, `decrypt`,
`clean`, `smudge`, `status`, `version`. `clean`/`smudge` are the ones
invoked by git itself via the filter driver; the rest are user-facing.

## Tooling & CI

- Go 1.23, module path `github.com/ducduyn31/git-vault`.
- `flake.nix`: devShell (go, golangci-lint, goreleaser, gofumpt) and a
  package output (`buildGoModule`) so `nix run` builds/runs the binary.
- GitHub Actions: one workflow for lint (golangci-lint) + test + build on
  push/PR; a separate goreleaser workflow triggered on tag push.
- `.golangci.yml`, `Makefile` (build/test/lint/fmt/install), `.gitignore`,
  `README.md` skeleton, `LICENSE` (MIT), `.editorconfig`.
- One stdlib-only smoke test (root cobra command executes without error)
  so CI has something real to pass.

## Testing strategy (scaffold-level)

Only a placeholder smoke test is included at this stage, per project
scope (scaffold, not implementation). Real unit tests land alongside the
keyservice/vault/gitattr implementations in follow-up work.
