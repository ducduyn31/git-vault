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

**Status:** early — encrypt/decrypt, the clean/smudge filter, status
reporting, key rotation, and cross-provider migration all work today.
GCP KMS, AWS KMS, Azure Key Vault, and HashiCorp Vault are all available
as team key-sharing providers, authorized through your org's existing
Google Workspace, AWS IAM Identity Center, Microsoft Entra ID SSO, or
Vault token — see [docs/gcpkms-provider.md](docs/gcpkms-provider.md),
[docs/awskms-provider.md](docs/awskms-provider.md),
[docs/azurekms-provider.md](docs/azurekms-provider.md), and
[docs/vault-provider.md](docs/vault-provider.md).

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
file is currently plaintext in your working tree — reinstall before staging
it, or handle it manually, or it'll be committed as plaintext to history.

Check what's tracked and its current encryption state at any time:

```sh
git vault status
```

To seal or open a file outside of git's stage/checkout path:

```sh
git vault encrypt secrets/prod.yaml
git vault decrypt secrets/prod.yaml
```

## AI coding agents

git-vault ships its own agent skill, so an AI coding agent working in the
repo knows the command surface and the rules around it (never commit a
tracked file as plaintext, check `git vault status` first, and so on):

```sh
npx skills add ducduyn31/git-vault
```

That's the [`skills`](https://github.com/vercel-labs/skills) CLI — it knows
where 75+ agents keep their skills, so it prompts for which of yours to
install into. Add `-a claude-code -g -y` to pick an agent, install at the
user level, and skip the prompts.

Installing copies the file, so it won't follow later changes to this repo —
run `npx skills update git-vault` to pull a newer version.

No Node? It's one file. Copy
[skills/git-vault/SKILL.md](skills/git-vault/SKILL.md) to wherever your
agent looks — `.claude/skills/git-vault/SKILL.md`,
`~/.codex/skills/git-vault/SKILL.md`, and so on.

## Team key-sharing with a shared key

For a shared key backed by your org's existing SSO (rather than a local
per-machine key or an out-of-band passphrase), see
[docs/gcpkms-provider.md](docs/gcpkms-provider.md) (Google Workspace
SSO), [docs/awskms-provider.md](docs/awskms-provider.md) (AWS IAM
Identity Center / SSO), [docs/azurekms-provider.md](docs/azurekms-provider.md)
(Microsoft Entra ID / `az login`), or
[docs/vault-provider.md](docs/vault-provider.md) (a self-hosted or HCP
Vault cluster / `vault login`).

## Development

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for build, test, and lint
commands.

## Security

Found a vulnerability? Don't open a public issue — see
[SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE).
