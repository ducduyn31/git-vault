---
name: git-vault
description: Use when working in a repository that contains a .git-vault.yaml file, or when the user asks to encrypt, decrypt, track, or share secret files kept in git. Covers the git-vault CLI — installing the filter driver, tracking patterns, checking encryption state, rotating keys, and switching key providers.
---

# git-vault

`git-vault` encrypts secret files transparently through a git filter driver
(the same mechanism git-lfs uses). Tracked files are ciphertext in git
history and plaintext in the working tree. Encryption is built on
[sops](https://github.com/getsops/sops)' keyservice protocol, so who can
decrypt is decided by the configured key provider.

## Detecting it

A repo uses git-vault if `.git-vault.yaml` exists at its root. That file
records the provider (`local`, `passphrase`, `gcpkms`, `awskms`,
`azurekms`, `vault`) and, for remote providers, the key resource ID. The
patterns that are encrypted live in `.gitattributes` as `filter=git-vault`
lines.

## Before touching secrets

Run `git vault status` first. It lists every tracked file and whether it is
currently `encrypted` or `plaintext` in the working tree. If a tracked file
reads as `plaintext`, the filter driver is not registered on this machine —
staging it would commit the secret in the clear. Run `git vault install` to
register the driver before staging anything.

## Commands

```sh
git vault install                 # register the filter driver, generate this machine's key
git vault install --global        # register it in the user's global git config instead
git vault install --provider gcpkms --key-resource-id <id>
git vault uninstall               # unregister the driver (--purge-config/--purge-attrs/--purge-keys)

git vault track "secrets/*.yaml"  # add a pattern to .gitattributes
git vault status                  # tracked files and their encryption state
git vault login                   # verify this machine is authorized for the repo's provider

git vault encrypt secrets/prod.yaml   # seal a file in place, outside the filter path
git vault decrypt secrets/prod.yaml   # open a file in place, outside the filter path

git vault rotate                  # new key, re-seal every tracked file under it
git vault migrate --provider awskms --key-resource-id <arn>   # re-seal under a different provider
```

Normal day-to-day work needs none of these: once `install` and `track` are
done, `git add`, `git commit`, `git checkout`, and `git pull` handle
encryption on their own.

## Rules when acting on a git-vault repo

- Never paste the plaintext contents of a tracked file into a commit
  message, an issue, a PR description, a log, or a chat message. Reading
  the file to make an edit is fine; reproducing its contents elsewhere is
  not.
- Never commit the ciphertext of a file you decrypted with
  `git vault decrypt` and then re-saved by hand — let the filter re-encrypt
  it on stage, or run `git vault encrypt` explicitly.
- Do not add a secret file to git before `git vault track` covers its path.
  Check with `git vault status` that the pattern actually matches.
- If a command fails with a provider or credential error, run
  `git vault login` — git-vault fails closed on purpose rather than
  committing plaintext.
- `git vault rotate` and `git vault migrate` rewrite every tracked file.
  Confirm with the user before running either.

## Installing

```sh
go install github.com/ducduyn31/git-vault/cmd/git-vault@latest
```

Provider setup for team key-sharing is documented in the repo's
`docs/` directory: `gcpkms-provider.md`, `awskms-provider.md`,
`azurekms-provider.md`, and `vault-provider.md`.
