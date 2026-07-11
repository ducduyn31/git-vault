# Azure Key Vault provider

git-vault's `azurekms` provider authorizes encrypt/decrypt through an
Azure Key Vault key, using whatever Azure credentials are already active
on your machine — `DefaultAzureCredential`. For most teams that means
`az login`, whether run directly or by whatever your org's Microsoft
Entra ID SSO already set up.

## 1. Admin bootstrap (one-time, done by whoever owns the Azure subscription)

    az keyvault create \
      --name git-vault-kv \
      --resource-group my-resource-group \
      --location eastus

    az keyvault key create \
      --vault-name git-vault-kv \
      --name git-vault-key \
      --kty RSA \
      --size 2048

    az role assignment create \
      --role "Key Vault Crypto User" \
      --assignee-object-id <group-or-user-object-id> \
      --scope $(az keyvault show --name git-vault-kv --query id -o tsv)

Note the key's fully-qualified URL, **including its version** (git-vault
requires the version explicitly — see Troubleshooting below):

    az keyvault key show \
      --vault-name git-vault-kv \
      --name git-vault-key \
      --query key.kid -o tsv

This prints something like
`https://git-vault-kv.vault.azure.net/keys/git-vault-key/abc123def456`.

## 2. Per-repo setup

    git vault install --provider azurekms \
      --key-resource-id https://git-vault-kv.vault.azure.net/keys/git-vault-key/abc123def456

This validates the URL immediately with a real encrypt/decrypt round
trip — a typo'd URL fails here, not at your first commit.

Add `--auto-login` to skip the confirmation prompt described below (see
"Auto-login" below) for every developer on this repo. It's persisted to
`.git-vault.yaml` as `auto_login: true`, so it's a one-time, team-wide,
repo-committed decision.

## 3. Per-developer setup

    git vault login

`git vault login` checks whether `DefaultAzureCredential` already
resolves to something that can use the configured key. If not, and `az`
is on your PATH, it offers to run `az login` for you (with confirmation
— it opens a browser and writes credentials to disk, so it never runs
without an explicit yes). Decline, or run it yourself first, and login
falls back to just telling you the exact command to run.

### Auto-login

If `.git-vault.yaml` has `auto_login: true` (see `--auto-login` above),
`git vault login` and `git vault install` skip the confirmation prompt
and run `az login` immediately when credentials are missing. Useful for
a team that's already decided every developer authenticates this way;
`az` still has to be on PATH, and it still opens a real browser window —
this only removes the extra keystroke, not the login flow itself.

## 4. Rotation

Azure Key Vault key rotation (automatic or via `az keyvault key rotate`)
only keeps old key versions passively decryptable — it never lets you
retire one, and the version baked into `.git-vault.yaml`'s
`key_resource_id` doesn't automatically follow a rotation performed in
Azure. Run `git vault rotate` periodically (or after a suspected key
exposure) to re-resolve the key's current version, persist it, and force
every tracked file's wrapped data key onto that version:

    git vault rotate
    git add -A && git commit -m "Rotate git-vault key"

Once every commit that matters has gone through a rotation, the old
version can be safely disabled:

    az keyvault key set-attributes \
      --vault-name git-vault-kv --name git-vault-key --version <old-version> \
      --enabled false

## Switching keys

To move to a different Key Vault key entirely (e.g. a different vault or
subscription), use `git vault migrate`, not `rotate` — `rotate` only
re-resolves the *current* version of the *same* key.

    git vault migrate --provider azurekms \
      --key-resource-id https://other-vault.vault.azure.net/keys/git-vault-key/<version>

## Troubleshooting

- `403` / access denied — your account isn't granted the `Key Vault
  Crypto User` role (or an access policy with wrap/unwrap key
  permissions) on the vault. Ask whoever ran the admin bootstrap step to
  add you (or your group).
- `"..." is not a valid Key Vault key URL, want https://<vault>.vault.azure.net/keys/<name>/<version>`
  — either the URL doesn't match that shape, or it's missing the version
  segment. git-vault always requires the version explicitly (no "latest"
  auto-resolution); copy the full value from `az keyvault key show
  --query key.kid`.
- "azurekms: no Azure credentials found — run `az login` first" —
  exactly that: no credential source (env vars, workload identity,
  managed identity, or a cached `az`/`azd`/PowerShell login) resolved on
  this machine yet.
