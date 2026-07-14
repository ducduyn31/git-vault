# HashiCorp Vault provider

git-vault's `vault` provider authorizes encrypt/decrypt through a
HashiCorp Vault Transit key, using whatever bearer token is already
active on your machine: the `VAULT_TOKEN` environment variable, falling
back to `~/.vault-token` (the file the `vault` CLI's `vault login` writes).

## 1. Admin bootstrap (one-time, done by whoever administers the Vault cluster)

    vault secrets enable transit
    vault write -f transit/keys/git-vault-key

    vault policy write git-vault-key - <<EOF
    path "transit/encrypt/git-vault-key" {
      capabilities = ["update"]
    }
    path "transit/decrypt/git-vault-key" {
      capabilities = ["update"]
    }
    EOF

Grant that policy to whichever auth method your team logs in with (e.g.
`vault write auth/userpass/users/<user> policies=git-vault-key` or the
equivalent for LDAP/OIDC/GitHub/AppRole). The key's URL for
`--key-resource-id` is built from your Vault address, the engine path, and
the key name:

    https://<vault-addr>:8200/v1/transit/keys/git-vault-key

## 2. Per-repo setup

    git vault install --provider vault \
      --key-resource-id https://<vault-addr>:8200/v1/transit/keys/git-vault-key

This validates the URL immediately with a real encrypt/decrypt round trip
— a typo'd URL or missing permission fails here, not at your first commit.

Add `--auto-login` to skip the confirmation prompt described below for
every developer on this repo. It's persisted to `.git-vault.yaml` as
`auto_login: true`, so it's a one-time, team-wide, repo-committed decision.

## 3. Per-developer setup

    git vault login

`git vault login` checks whether a valid token (`VAULT_TOKEN` or
`~/.vault-token`) already authorizes the configured key. If not, and
`vault` is on your PATH, it offers to run `vault login` for you (with
confirmation — it writes a token to disk, so it never runs without an
explicit yes). This only runs the default token auth method — if your org
uses OIDC, LDAP, GitHub, or AppRole, run your own
`vault login -method=<method>` first, then re-run `git vault login`.

### Auto-login

If `.git-vault.yaml` has `auto_login: true` (see `--auto-login` above),
`git vault login` and `git vault install` skip the confirmation prompt and
run `vault login` immediately when no valid token is found. `vault` still
has to be on PATH; this only removes the extra keystroke, not the login
flow itself.

## 4. Rotation

Vault Transit key rotation (`vault write -f transit/keys/git-vault-key/rotate`)
only keeps old key versions passively decryptable, governed by the key's
`min_decryption_version` — it never retires one automatically. Run
`git vault rotate` periodically (or after a suspected key exposure) to
force every tracked file's wrapped data key onto the key's current
version:

    vault write -f transit/keys/git-vault-key/rotate
    git vault rotate
    git add -A && git commit -m "Rotate git-vault key"

Unlike `azurekms`, `--key-resource-id` never encodes a version, so
`git vault rotate` doesn't rewrite `.git-vault.yaml` for this provider —
only the ciphertext changes.

Once every commit that matters has gone through a rotation, retire the old
version:

    vault write transit/keys/git-vault-key/config min_decryption_version=<new-version>

## Switching keys

To move to a different Transit key entirely (e.g. a different Vault
cluster or engine mount), use `git vault migrate`, not `rotate` —
`rotate` only re-seals under the *same* key's current version.

    git vault migrate --provider vault \
      --key-resource-id https://other-vault-addr:8200/v1/transit/keys/git-vault-key

## Troubleshooting

- `403` / permission denied — either no valid token was found, or the
  token's ACL policy doesn't grant `update` on
  `transit/encrypt/<key>`/`transit/decrypt/<key>`. Run `git vault login`,
  or ask whoever ran the admin bootstrap step to grant your policy.
- A malformed `--key-resource-id` fails with sops's own Vault URL parsing
  error, which names the expected shape
  (`https://vault.example.com:8200/v1/transit/keys/keyName`).
- "hcvault: no valid Vault token — run `vault login` first" — exactly
  that: no `VAULT_TOKEN` env var and no `~/.vault-token` file resolved a
  token Vault accepted for this key.
