# git-vault: UX safety design (prior-art review of git-sops)

Date: 2026-07-10
Status: approved

## Purpose

Before finalizing git-vault's git-integration UX, we reviewed the existing
`git-sops` project (github.com/cycneuramus/git-sops), a similar clean/
smudge filter integration for sops, to learn from its design and avoid
repeating its mistakes. Its biggest weakness: several of its own design
choices make it easy for a user to accidentally commit a secret in
plaintext, silently, with no warning.

## What git-sops does

- Clean/smudge filter driver, configured via `.gitattributes` — same
  mechanism git-vault also uses.
- Selective encryption is opt-in **per line**, via a literal comment
  marker (`#enc!`) that must be placed above the secret line(s) in a file;
  everything else is left in plaintext.
- "Is this file already encrypted?" is determined by scanning file
  content for the literal substring `ENC[` — the project's own README
  calls this "a bit fragile."
- The filter is registered locally per repo via `git-sops init`, which
  writes to that repo's local (non-versioned) git config. Nothing in the
  README sets `filter.crypt.required`.
- The README's own example config assigns an `AGE-SECRET-KEY-...` value
  (an age *private* key) to the `age:` field of a `creation_rules` entry,
  which is documented upstream (age/sops) as the *public recipient* field.

## Risks this creates (why a user can accidentally commit a password)

1. **Opt-in-per-line via a forgettable marker.** Add a secret above/
   outside the `#enc!` block, or a new file where you forget the marker
   entirely, and it's committed in plaintext with no error. There's no
   schema saying "these keys are always secret" — it's manual and
   unenforced.
2. **Fail-open filter.** Without `required = true`, git's default
   behavior when a filter command errors or isn't registered is to pass
   raw content straight through. Combined with per-repo local-only init
   (not carried by clone), a fresh clone where the user forgot to rerun
   `git-sops init` will commit plaintext with no warning at all.
3. **Substring-scan state detection.** Determining "encrypted" by
   scanning for `ENC[` rather than validating real sops metadata risks
   false negatives/positives about a file's true state.
4. **Config example mixes secret and public key material,** inviting a
   user to put a private key where a public recipient is expected.

## git-vault's answering design decisions

| git-sops risk | git-vault's answer |
|---|---|
| Per-line comment-marker opt-in | Encryption scope is decided by `.gitattributes` pattern (whole matched file) plus sops's own structural key-path rules for partial YAML/JSON encryption (`.sops.yaml`) — never a magic string a human has to remember to type per secret. |
| Fail-open filter | `git vault install` always sets `filter.git-vault.required true`. A clean/smudge error aborts the git operation rather than passing content through. |
| Local-only per-repo init, easy to forget on a fresh clone | `git vault install --global` registers the filter driver in the user's global git config (git-lfs's pattern), so any repo cloned afterward is protected immediately. |
| Substring-scan detection | `git vault status` checks real sops metadata (the file's `sops:` block/MAC), not a text scan. |
| Secret material in config that could be shared/committed | Repo-tracked `.git-vault.yaml` holds only non-secret settings (provider name, issuer URL, client id); actual key/session material lives only in `~/.cache/git-vault/`, which nothing ever stages. |

## Decision: no auto-installed pre-commit hook

Considered adding a pre-commit hook (installed by `git vault install`)
that independently re-verifies staged vault-tracked files are encrypted
before allowing a commit — the strongest possible net. Decided against
auto-installing it: it risks clobbering or conflicting with a repo's
existing hook manager (husky, the `pre-commit` framework, etc.), and the
fail-closed filter already covers the primary failure mode (the filter
itself erroring). `git vault status` remains available for a user or
their own CI/hook setup to call if they want that extra check — just not
installed automatically.
