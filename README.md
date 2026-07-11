# git-vault

Secrets belong in your repo, not in a wiki page or a shared password vault
nobody remembers to update. `git-vault` encrypts secret files transparently,
so `git add`, `git commit`, `git checkout`, and `git pull` just work — the
plaintext only ever touches disk in your working tree, never in git history.

- **Transparent.** A git filter driver (the same mechanism git-lfs uses)
  encrypts on stage and decrypts on checkout. No wrapper commands to
  remember for day-to-day use.
- **Fail-closed.** If a key or provider isn't available, git aborts the
  operation instead of silently committing plaintext.
- **Pluggable keys.** Encryption is built on
  [sops](https://github.com/getsops/sops)'s keyservice protocol, so who can
  decrypt is a matter of which key provider is configured — not a
  hardcoded scheme.

**Status:** early — encrypt/decrypt, the clean/smudge filter, and status
reporting work today using a local per-machine key. Team key-sharing
providers (SSO, etc.) are on the roadmap; `git vault login` isn't
implemented yet.

## Configure git-vault in a project

```sh
# 1. Install the binary
go install github.com/ducduyn31/git-vault/cmd/git-vault@latest

# 2. From inside the repo, register the filter driver and generate
#    this machine's key
git vault install

# 3. Track the files you want encrypted
git vault track "secrets/*.yaml"

# 4. Commit as normal — tracked files are sealed automatically
git add .gitattributes secrets/
git commit -m "Track secrets with git-vault"
```

`git vault install --global` registers the filter driver in your global
git config instead, so any repo you clone afterwards is protected
immediately.

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

Check what's tracked and its current encryption state at any time:

```sh
git vault status
```

To seal or open a file outside of git's stage/checkout path:

```sh
git vault encrypt secrets/prod.yaml
git vault decrypt secrets/prod.yaml
```

## Development

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for build, test, and lint
commands.
