# GCP KMS provider

git-vault's `gcpkms` provider authorizes encrypt/decrypt through a GCP
KMS key, using whatever Google credentials are already active on your
machine — Application Default Credentials (ADC). For most teams that
means whatever your org's Google Workspace SSO already set up.

## 1. Admin bootstrap (one-time, done by whoever owns the GCP project)

    gcloud kms keyrings create git-vault \
      --location=global

    gcloud kms keys create git-vault-key \
      --location=global \
      --keyring=git-vault \
      --purpose=encryption

    gcloud kms keys add-iam-policy-binding git-vault-key \
      --location=global \
      --keyring=git-vault \
      --member="group:engineering@example.com" \
      --role="roles/cloudkms.cryptoKeyEncrypterDecrypter"

Note the full resource ID (printed by `gcloud kms keys create`, or built
yourself):

    projects/<project>/locations/global/keyRings/git-vault/cryptoKeys/git-vault-key

## 2. Per-repo setup

    git vault install --provider gcpkms \
      --key-resource-id projects/<project>/locations/global/keyRings/git-vault/cryptoKeys/git-vault-key

This validates the resource ID immediately with a real encrypt/decrypt
round trip — a typo'd path fails here, not at your first commit.

Add `--auto-login` to skip the confirmation prompt described
below (see "Auto-login" below) for every developer on this repo. It's
persisted to `.git-vault.yaml` as `auto_login: true`, so it's a
one-time, team-wide, repo-committed decision.

## 3. Per-developer setup

    git vault login

`git vault login` checks whether ADC already resolves to something that
can use the configured key. If not, and `gcloud` is on your PATH, it
offers to run `gcloud auth application-default login` for you (with
confirmation — it opens a browser and writes credentials to disk, so it
never runs without an explicit yes). Decline, or run it yourself first,
and login falls back to just telling you the exact command to run.

### Auto-login

If `.git-vault.yaml` has `auto_login: true` (see `--auto-login`
above), `git vault login` and `git vault install` skip the confirmation
prompt and run `gcloud auth application-default login` immediately when
ADC is missing. Useful for a team that's already decided every developer
authenticates this way; `gcloud` still has to be on PATH, and it still
opens a real browser window — this only removes the extra keystroke, not
the login flow itself.

## 4. Rotation

GCP's automatic key rotation only keeps old key versions passively
decryptable — it never lets you retire one. Run `git vault rotate`
periodically (or after a suspected key exposure) to force every tracked
file's wrapped data key onto the current primary key version:

    git vault rotate
    git add -A && git commit -m "Rotate git-vault key"

Once every commit that matters has gone through a rotation, the old
version(s) can be safely disabled or destroyed:

    gcloud kms keys versions disable <version> \
      --location=global --keyring=git-vault --key=git-vault-key
    gcloud kms keys versions destroy <version> \
      --location=global --keyring=git-vault --key=git-vault-key

## Switching keys

To move to a different GCP KMS key entirely (e.g. a different project or
region), use `git vault migrate`, not `rotate` — `rotate` assumes the
resource ID is unchanged and only re-wraps under the current key's
primary version:

    git vault migrate --provider gcpkms \
      --key-resource-id projects/<other-project>/locations/global/keyRings/git-vault/cryptoKeys/git-vault-key

## Troubleshooting

- `PermissionDenied` / `403` — your account isn't granted
  `roles/cloudkms.cryptoKeyEncrypterDecrypter` on the key. Ask whoever ran
  the admin bootstrap step to add you (or your group).
- `no valid resource ID found in "..."` — the `--key-resource-id` doesn't
  match `projects/P/locations/L/keyRings/R/cryptoKeys/K`. Copy it exactly
  from `gcloud kms keys create`'s output or `gcloud kms keys list`.
- "gcpkms: no Google credentials found — run `gcloud auth application-default
  login` first" — exactly that: ADC hasn't been set up on this machine
  yet.
