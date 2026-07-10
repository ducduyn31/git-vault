# git-vault: project scaffold design

Date: 2026-07-10
Status: approved (scaffold only — no crypto/backend logic implemented yet)

## Purpose

`git-vault` is a Go-based git extension that transparently encrypts secret
files in a repository, using a pluggable backend to source the decryption
key from an SSO-gated source (e.g. an internal identity provider). This
document specs the initial professional project scaffold: repo layout,
tooling, CI, and package boundaries. It does not implement encryption or
any real backend — those are separate follow-up specs/plans.

## Non-goals (for this scaffold)

- No real SSO backend implementation (only a stub/mock `Backend`).
- No real sops integration logic beyond a wrapper package stub.
- No published releases; goreleaser config exists but is not exercised.

## Git integration model

Modeled directly on git-lfs, which is the established pattern for "git
extension that transforms file content on checkout/commit":

1. **Filter driver.** `git vault install` registers a git filter driver:
   `filter.git-vault.clean`, `filter.git-vault.smudge`,
   `filter.git-vault.required true`. Git invokes
   `git-vault clean`/`git-vault smudge` with file content on stdin and
   expects transformed content on stdout — no file paths, no interactivity,
   no tty.
2. **Attribute tracking.** `git vault track "<pattern>"` appends a line to
   `.gitattributes`: `<pattern> filter=git-vault diff=git-vault -text`
   (same shape as `git lfs track`). git-vault does not need its own
   pattern-tracking config file — `.gitattributes` is the single source of
   truth, and commands like `status` parse it for `filter=git-vault` lines
   when they need the tracked set.
3. **Explicit mode.** `git vault encrypt/decrypt <file>` performs the same
   seal/open operation outside the filter path, for manual use or
   scripting.

### Auth is decoupled from the filter path

Git filters run in contexts with no tty and may run concurrently or
non-interactively (e.g. during a parallel checkout). A filter must never
block on an interactive SSO prompt. So:

- `git vault login` performs the SSO flow once (interactively) and caches a
  short-lived session/data key locally (`~/.cache/git-vault/`).
- `clean`/`smudge`/`encrypt`/`decrypt` only ever *read* the cached session.
  If it's missing or expired, they fail fast with a message telling the
  user to run `git vault login` — they never attempt to trigger a login
  themselves.

## Encryption engine

Rather than reimplementing structured partial-file encryption (only
encrypt the values in a YAML/JSON/ENV file, keep keys/structure readable),
git-vault vendors `go.mozilla.org/sops/v3`, which already solves this and
already has a pluggable keyservice concept. git-vault's own code is:

- A CLI (git-lfs-shaped UX) and git integration (filter/attributes/session
  cache), plus
- A `Backend` interface that supplies sops with a data key, backed by the
  cached SSO session.

This keeps the crypto/file-format surface entirely in a well-audited
upstream library; git-vault only owns key sourcing and git plumbing.

## Package layout

```
cmd/git-vault/          main.go — cobra root, wires subcommands
internal/cli/           login, track, install, encrypt, decrypt, clean, smudge, status, version
internal/backend/       Backend interface (Login/GetDataKey) + registry; stub backend only for now
internal/session/       local session cache (~/.cache/git-vault): read/write, expiry check
internal/vault/         wraps sops using a session-supplied key (Seal/Open, streaming for clean/smudge)
internal/gitattr/       read/write .gitattributes track lines (git-lfs-style)
internal/config/        backend selection + session settings (not pattern tracking)
```

Each package has one job:
- `internal/backend` never knows about sops or git.
- `internal/vault` never knows about SSO or git plumbing — it takes a key
  and file bytes.
- `internal/gitattr` never knows about encryption — it only edits
  `.gitattributes` lines.
- `internal/session` never knows about sops or backends — it's a generic
  cache-with-expiry.

This means each can be tested and reasoned about independently, and a real
backend/crypto implementation later touches `internal/backend` and
`internal/vault` without needing changes to `internal/cli`, `internal/
gitattr`, or `internal/session`.

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
backend/vault/gitattr implementations in follow-up work.
