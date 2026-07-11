# AWS KMS provider (git-vault's second cloud KMS provider)

## Purpose

`gcpkms` (docs/superpowers/specs/2026-07-11-gcpkms-provider-design.md) proved
the pattern: a thin `keyservice.Provider` wrapping a sops KMS `MasterKey`,
authorized through whatever ambient cloud credentials are already active,
with no git-vault-operated service in the loop. This spec adds the second
provider on that pattern: AWS KMS, authorized through the AWS SDK's default
credential chain (env vars, shared config/credentials file, or — for team
key-sharing via SSO — a named profile set up with `aws configure sso`). This
closes the README's "AWS ... on the roadmap" line for AWS specifically.

## Why AWS KMS, and why the default credential chain

Same rationale as gcpkms: sops already vendors
`github.com/getsops/sops/v3/kms`, a `MasterKey` backed by
`aws-sdk-go-v2/service/kms`, already a transitive dependency via the pinned
sops version. No new external dependency, no git-vault-operated key server —
AWS IAM (a key policy plus, for SSO users, the permission set/role granted
`kms:Encrypt`/`kms:Decrypt`) is the only access control.

AWS's per-developer login is multi-step compared to GCP's single
`gcloud auth application-default login`: a one-time
`aws configure sso --profile <name>` (registers the SSO start URL/region for
that profile) followed by a per-session `aws sso login --profile <name>`
once the cached token expires. Because of this, `awskms` supports an
optional named profile (`--aws-profile`, sops's `MasterKey.AwsProfile`)
rather than assuming the default profile always applies — teams pin
different profiles per AWS account/role.

## Non-goals

- **No admin-bootstrap command.** `aws kms create-key` plus a key policy
  grant is documented as CLI snippets in docs/awskms-provider.md, not
  wrapped in a new git-vault subcommand — same call as gcpkms.
- **No STS role-assumption UI.** Sops's `kms.NewMasterKeyFromArn` already
  parses a `<key-arn>+arn:<role-arn>` suffix into `MasterKey.Role` and
  transparently assumes it via STS before every Encrypt/Decrypt. git-vault
  passes whatever string it's given straight through — if a user wants role
  assumption, they compose it into `--key-resource-id` themselves; no new
  flag or validation needed for it to work.
- **Not a bulletproof credential-error classifier.** AWS's "no credentials
  configured at all" case is not a single clean signal the way GCP's
  ADC-missing message is — it falls through the SDK's full default chain
  (env → shared config → SSO → container creds → EC2 IMDS) and surfaces as
  a generic wrapped error after an IMDS timeout (empirically ~1s, but not a
  documented guarantee). Only the one AWS SDK exposes as a distinct typed
  error — `ssocreds.InvalidTokenError`, an expired/invalid cached SSO
  session — gets the interactive "run the fix for me" treatment. Every
  other failure (never configured, IAM denied, malformed ARN) is surfaced
  as-is with a static hint, not auto-diagnosed.

## Architecture

```
git vault install --provider awskms \
    --key-resource-id arn:aws:kms:<region>:<account>:key/<id> \
    [--aws-profile <name>]
  → .git-vault.yaml: {provider: awskms, key_resource_id: "arn:...", aws_profile: "<name>"}
  → validates the ARN immediately via the same round trip login uses

git vault login
  → attempts a harmless encrypt/decrypt round trip against the configured
    ARN, using the named profile if set, else the default credential chain
  → success: "already logged in"
  → failure, expired/invalid SSO session (errors.As on
    awskms.ErrExpiredSSOSession): offers to run
    `aws sso login [--profile <profile>]` (confirmation required — it
    opens a browser), then retries the round trip once
  → failure, anything else: surfaces the wrapped AWS error plus a hint to
    run `aws configure sso --profile <profile>` if this is first-time setup

encrypt / decrypt / clean / smudge
  → internal/keyservice/awskms.Provider wraps sops's kms.MasterKey
  → Encrypt(ctx, keyID, plaintext):
      NewMasterKeyFromArn(keyID, nil, awsProfile) → EncryptContext → EncryptedDataKey()
  → Decrypt(ctx, keyID, ciphertext):
      NewMasterKeyFromArn(keyID, nil, awsProfile) → SetEncryptedDataKey → DecryptContext
  → keyID is the AWS KMS ARN, carried opaquely as "awskms:<arn>" through the
    same age-recipient convention gcpkms/local/passphrase already use — no
    changes to internal/vault or the sops tree format
```

## Rotation (`git vault rotate`)

Unlike GCP, AWS KMS's automatic annual key rotation is *fully* transparent:
there is no user-visible "key version" to disable or destroy — Decrypt
always succeeds against whatever backing material originally encrypted a
given ciphertext, forever, with no API to retire it. So re-sealing every
file (the same mechanic gcpkms's rotate case uses) does not give AWS users
the same crypto-shredding payoff GCP users get from
`gcloud kms keys versions disable/destroy`.

`internal/cli/rotate.go` still gets a `case awskms.Name` — it's the same
few lines as gcpkms's case (`oldVault == newVault`, since ARN/profile don't
change) — but the follow-up message says so plainly: rotation here is
defense-in-depth re-encryption only, and anyone who actually needs to
retire a compromised key should `git vault migrate` to a *different* KMS
key (a new ARN) instead, since that's the only way to stop depending on
specific backing material.

## Components touched

- **New: `internal/keyservice/awskms/awskms.go`.** A `Provider` implementing
  `Name()`, `Encrypt`, `Decrypt` by wrapping sops's `kms.MasterKey`. Package
  scoped test overrides (`SetTestOverridesForTesting`) inject a fake
  `http.Client` and a static `aws.CredentialsProvider`, mirroring gcpkms's
  `SetClientOptionsForTesting`.
- **New: `internal/keyservice/awskms/awskmstest/awskmstest.go`.** A fake AWS
  KMS server. AWS's SDK has no public endpoint-override hook like GCP's
  `option.ClientOption` (the `MasterKey.baseEndpoint` field sops added is
  unexported, for its own tests only), so this fakes at the HTTP layer
  instead of gRPC: a plain `httptest.Server` handler dispatches on the
  `X-Amz-Target: TrentService.Encrypt`/`.Decrypt` header, decodes the JSON
  body (`KeyId`, base64 `Plaintext`/`CiphertextBlob`), and returns a
  marker-prefixed fake ciphertext — same "prove real data flows through the
  real MasterKey without real crypto" trick gcpkmstest uses. The returned
  `*http.Client`'s `Transport` rewrites every outbound request's
  scheme/host to the fake server's, regardless of the region-derived host
  the SDK resolves.
- **`internal/config/config.go`:** add
  `AwsProfile string \`yaml:"aws_profile,omitempty"\``. `KeyResourceID` is
  reused as-is for the AWS ARN (already provider-generic naming; no new
  field for it).
- **`internal/cli/vault.go`:** `newAWSKMSVault(cfg)` builder (mirrors
  `newGCPKMSVault`) and a new `case awskms.Name` in `vaultForProvider`'s
  switch.
- **`internal/cli/install.go`:** accept `awskms` in `--provider`, add
  `--aws-profile` flag (optional; ignored for other providers), require
  `--key-resource-id` when provider is `awskms` (same check shape as the
  existing gcpkms one), validate via the round trip.
- **`internal/cli/login.go`:** restructure the current
  `if cfg.Provider != gcpkms.Name { error }` single-provider check into a
  `switch cfg.Provider { case gcpkms.Name: ...; case awskms.Name: ...;
  default: error }`. The existing gcpkms case (including its interactive
  `gcloud` prompt) is preserved verbatim. The new awskms case does the
  round trip and, on `errors.As(err, &*ssocreds.InvalidTokenError)`, offers
  to run `aws sso login [--profile <profile>]` the same
  confirm-before-exec way.
- **`internal/cli/rotate.go`:** add `case awskms.Name` per the Rotation
  section above.
- **`internal/cli/migrate.go`:** add a `--aws-profile` flag; require
  `--key-resource-id` when `--provider awskms`, same shape as the existing
  gcpkms check. The existing recipient-comparison guard
  (`oldRecipients[0] == newRecipients[0]`) needs no change: the recipient
  string only encodes `awskms:<arn>`, not the profile, so migrating between
  two different ARNs is correctly allowed and re-installing the same ARN
  under a different `--aws-profile` is correctly rejected as a no-op (the
  profile only changes which credentials authenticate to the same key, not
  which key is used).
- **New: `docs/awskms-provider.md`.** User-facing setup guide (content
  written during implementation): admin bootstrap (`aws kms create-key` +
  key policy grant to an IAM Identity Center permission set or IAM
  group/role), per-repo setup, per-developer setup
  (`aws configure sso` once, `aws sso login` per session, `git vault
  login`), rotation caveat (see above), switching keys via `migrate`,
  troubleshooting (permission denied surfaced as-is, malformed ARN caught
  at install time, expired SSO session auto-prompted).
- **README.md:** link `docs/awskms-provider.md`; update the "AWS, Azure...
  on the roadmap" line to drop AWS.

## Error handling

- Expired/invalid cached SSO token (`*ssocreds.InvalidTokenError`, detected
  via `errors.As`) → `awskms.ErrExpiredSSOSession` sentinel, which
  `internal/cli/login.go` catches to offer running
  `aws sso login [--profile <profile>]` interactively (confirmation
  required first, mirroring gcpkms's gcloud prompt).
- IAM permission denied on the KMS key → surfaced as-is from the AWS API
  (it names the missing action/resource); git-vault doesn't reinterpret it.
- Malformed `--key-resource-id` (not a valid KMS ARN) → caught at `install`
  time by the same round trip `login` uses.
- No credentials configured at all (first-time setup, no profile/env/IMDS
  resolves) → surfaced as the wrapped AWS SDK error, with a static hint to
  run `aws configure sso --profile <profile>` — not auto-detected or
  auto-fixed, per the Non-goals section.

## Testing

- `awskms.Provider` unit-tested against `awskmstest`'s fake HTTP server: a
  successful round trip, tampered-ciphertext failure, invalid-ARN failure,
  and `friendlyLoginErr` correctly rewriting a synthetic
  `ssocreds.InvalidTokenError` into `ErrExpiredSSOSession` while passing
  other errors through wrapped with `op`.
- `vaultForProvider`/`install`/`login`/`rotate`/`migrate` CLI tests extend
  the existing gcpkms fake-provider pattern with an awskms case each. The
  rotate test asserts the file's `enc` blob actually changes. The migrate
  test covers `awskms(A)→awskms(B)` (two different ARNs) specifically,
  exercising the same recipient-comparison logic gcpkms's migrate test
  already covers.
- No integration test against real AWS infrastructure — out of scope.
