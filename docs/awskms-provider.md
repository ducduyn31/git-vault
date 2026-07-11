# AWS KMS provider

git-vault's `awskms` provider authorizes encrypt/decrypt through an AWS
KMS key, using whatever AWS credentials the SDK's default credential
chain resolves on your machine — for most teams that means a named
profile set up with `aws configure sso` against your org's IAM Identity
Center (AWS SSO).

## 1. Admin bootstrap (one-time, done by whoever owns the AWS account)

    aws kms create-key --description "git-vault" \
      --tags TagKey=purpose,TagValue=git-vault

Note the `KeyId`/`Arn` printed in the output, or fetch it later:

    aws kms describe-key --key-id alias/git-vault --query KeyMetadata.Arn --output text

Grant the team access — either via a key policy statement naming an IAM
Identity Center permission set/role, or `kms:Encrypt`/`kms:Decrypt` in
that role's own IAM policy:

    aws kms create-grant --key-id <key-id> \
      --grantee-principal arn:aws:iam::<account>:role/<permission-set-role> \
      --operations Encrypt Decrypt

## 2. Per-repo setup

    git vault install --provider awskms \
      --key-resource-id arn:aws:kms:<region>:<account>:key/<key-id> \
      [--aws-profile <profile-name>]

This validates the ARN immediately with a real encrypt/decrypt round
trip — a typo'd ARN fails here, not at your first commit. `--aws-profile`
is optional; omit it to use the AWS SDK's default credential chain (env
vars, the default profile, or an instance role).

Add `--auto-login` to skip the confirmation prompt described below for
every developer on this repo. It's persisted to `.git-vault.yaml` as
`auto_login: true`, so it's a one-time, team-wide, repo-committed
decision (shared with gcpkms — see docs/gcpkms-provider.md).

## 3. Per-developer setup

    aws configure sso --profile <profile-name>   # one-time
    aws sso login --profile <profile-name>       # per session
    git vault login

`git vault login` checks whether the configured profile (or default
chain) already resolves to something that can use the configured key. If
the cached SSO session has expired or is missing, and `aws` is on your
PATH, it offers to run `aws sso login [--profile <profile-name>]` for
you (with confirmation — same as `--auto-login` above). Any other
failure (never ran `aws configure sso` yet, IAM denied, malformed ARN) is
surfaced as-is with a hint, since it isn't a single clean signal the way
an expired session is.

## 4. Rotation

Unlike GCP KMS, AWS KMS's automatic annual key rotation is fully
transparent — there's no key version to disable or destroy afterward;
Decrypt always works against whatever backing material originally
encrypted a given ciphertext, forever. Running `git vault rotate` still
re-seals every tracked file, forcing a fresh KMS `Encrypt` call:

    git vault rotate
    git add -A && git commit -m "Rotate git-vault key"

...but this is defense-in-depth re-encryption only, not a way to retire
old key material — AWS gives you no API to do that. If you actually need
to stop depending on specific key material (e.g. a suspected
compromise), create a new KMS key and use `git vault migrate` instead
(see below).

## Switching keys

To move to a different AWS KMS key (or a different provider entirely),
use `git vault migrate`, not `rotate`:

    git vault migrate --provider awskms \
      --key-resource-id arn:aws:kms:<region>:<account>:key/<new-key-id> \
      [--aws-profile <profile-name>]

## Troubleshooting

- `AccessDeniedException` — your role isn't granted
  `kms:Encrypt`/`kms:Decrypt` on the key. Ask whoever ran the admin
  bootstrap step to grant it.
- `no valid ARN found in '...'` — the `--key-resource-id` doesn't match
  `arn:aws:kms:<region>:<account>:key/<id>` (or `alias/<name>`). Copy it
  exactly from `aws kms describe-key`'s output.
- "awskms: AWS SSO session has expired or is invalid — run `aws sso
  login` first" — exactly that: the cached SSO token for this profile
  has expired or was never created; `git vault login` offers to fix it
  for you.
- Anything else (e.g. `aws configure sso` was never run for this
  profile) — the raw AWS SDK error is surfaced; run
  `aws configure sso --profile <profile-name>` once, then retry.
