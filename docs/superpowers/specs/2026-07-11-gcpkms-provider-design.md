# GCP KMS provider (git-vault's first SSO-backed key provider)

## Purpose

`internal/keyservice`'s `Provider` interface was built with SSO as its
first real backend in mind, but only a `StubProvider` exists today, and
`git vault login` errors with "not implemented in scaffold". This spec
adds a real provider: GCP Cloud KMS, authorized via whatever identity is
already active through Google's Application Default Credentials (ADC) —
which for most teams means SSO through Google Workspace via
`gcloud auth application-default login`. This closes the gap the README
calls out ("Team key-sharing providers (SSO, etc.) are on the roadmap").

## Why GCP KMS, and why ADC instead of a custom OIDC flow

The original scaffold design sketched `.git-vault.yaml`'s `issuer_url`/
`client_id` fields and `session.go`'s cached bearer token for a
hypothetical provider that does its own OAuth device-flow login against
an OIDC issuer, then hands the resulting identity to a git-vault-operated
key server for authorization. That's real work: git-vault would have to
build and run a service that verifies the token and holds the actual
unwrap key.

A cloud KMS sidesteps that entirely. GCP's client libraries already
resolve ADC (`gcloud auth application-default login` is itself a full
Google Workspace SSO browser flow), and access control is plain GCP IAM
on the KMS key — nothing for git-vault to build or operate. sops already
vendors `gcpkms.MasterKey` (`github.com/getsops/sops/v3/gcpkms`, already
a transitive dependency via `go.mod`'s `sops v3.13.2` pin), so the
provider is a thin adapter, not a new KMS client.

`session.go`'s doc comment already anticipated this path: "not every
Provider needs a session (e.g. a KMS-backed provider might use ambient
cloud credentials instead)". This provider takes that path; `session.go`
remains as-is for `local`/`passphrase` and is simply unused here.

GCP was chosen over AWS/Azure because `gcloud auth application-default
login` is a single command with no prior profile setup, versus AWS's
multi-step `aws configure sso` + `aws sso login`. Azure's `az login` is
comparably simple and would be a reasonable second provider later, using
the same `Provider` interface.

## Non-goals

- **No admin-bootstrap command.** Creating the KMS KeyRing/CryptoKey and
  granting IAM roles is a rare, high-privilege action performed by
  whoever already has KMS admin rights on the GCP project. It ships as
  documented `gcloud` commands (see docs/gcpkms-provider.md), not a new
  git-vault subcommand wrapping GCP's IAM Admin API.
- **No multi-region/multi-resource-ID support.** sops's `gcpkms` package
  already supports comma-separated resource IDs; nothing here blocks
  adding it later, but v1 is a single resource ID per repo.
- **No `git vault rotate` support for gcpkms.** GCP's own automatic
  CryptoKey rotation covers this; git-vault's rotate command explicitly
  rejects the gcpkms provider with a message pointing at that feature,
  rather than silently doing nothing.
- **No shelling out to the `gcloud` CLI.** Consistent with using sops as
  a library rather than a subprocess, `git vault login` never execs
  `gcloud` — it verifies ADC directly via the Go client library and
  prints the command for the user to run themselves if ADC is missing.

## Architecture

```
git vault install --provider gcpkms --key-resource-id projects/P/locations/L/keyRings/R/cryptoKeys/K
  → .git-vault.yaml: {provider: gcpkms, key_resource_id: "..."}
  → also validates the resource ID via the same round trip login uses

git vault login
  → attempts a harmless encrypt/decrypt round trip against the
    configured key using whatever ADC is currently resolvable
  → success: "already logged in as <ADC principal>"
  → failure: prints the exact `gcloud auth application-default login`
    command to run, and exits non-zero — git-vault never performs the
    OAuth flow itself

encrypt / decrypt / clean / smudge
  → internal/keyservice/gcpkms.Provider wraps sops's gcpkms.MasterKey
  → Encrypt(ctx, keyID, plaintext):
      NewMasterKeyFromResourceID(keyID) → EncryptContext → EncryptedDataKey()
  → Decrypt(ctx, keyID, ciphertext):
      NewMasterKeyFromResourceID(keyID) → SetEncryptedDataKey(ciphertext) → DecryptContext
  → keyID is the GCP KMS resource ID, carried opaquely through sops's
    age.Recipient field as "gcpkms:<resource-id>", exactly like
    local/passphrase already do (see internal/keyservice/server.go's
    "<provider>:<key-id>" convention) — no changes needed to
    internal/vault or the sops tree format.
```

## Components touched

- **New: `internal/keyservice/gcpkms/gcpkms.go`.** A `Provider`
  implementing `Name()`, `Encrypt`, `Decrypt` by wrapping sops's
  `gcpkms.MasterKey`. No new external dependency — `gcpkms` is already
  pulled in transitively by the pinned sops version.
- **`internal/config/config.go`:** add
  `KeyResourceID string `yaml:"key_resource_id,omitempty"``. The
  existing `IssuerURL`/`ClientID` fields, written for a hypothetical OIDC
  provider that was never built, stay unused by this feature and are
  noted here as dead — a future cleanup can remove them if no OIDC-based
  provider ever materializes.
- **`internal/cli/vault.go`:** `vaultForProvider(name string)` becomes
  `vaultForProvider(cfg config.Config)` (gcpkms needs `KeyResourceID`,
  where local/passphrase needed nothing from config beyond the provider
  name), plus a `newGCPKMSVault(cfg)` builder and a new
  `case gcpkms.Name` in the switch. Call sites in `install.go`,
  `migrate.go`, and `newVault()` update accordingly.
- **`internal/cli/install.go`:** accept `gcpkms` in `--provider`, add a
  `--key-resource-id` flag (required iff provider is gcpkms), persist it
  to config, and validate it via the same round trip `login` uses.
- **`internal/cli/login.go`:** real implementation, dispatching on
  `cfg.Provider`. For `gcpkms`: the verify-and-instruct round trip above.
  For `local`/`passphrase`: `"provider %q does not use git vault login"`
  instead of today's blanket stub error.
- **`internal/cli/rotate.go`:** add `case gcpkms.Name` that errors with a
  message pointing at GCP KMS's own automatic key rotation.
- **`internal/cli/migrate.go`:** no special-casing expected — it already
  resolves providers generically through `vaultForProvider`, so
  migrating a repo to/from gcpkms should work once the above lands.
- **New: `docs/gcpkms-provider.md`.** User-facing setup guide (see
  below) — content is written during implementation, not in this spec.
- **`README.md`:** add a link to `docs/gcpkms-provider.md` near
  "Configure git-vault in a project", and update the "Team key-sharing
  providers... are on the roadmap" line since this closes that gap.

## `docs/gcpkms-provider.md` contents (to be written)

- **Admin bootstrap** (one-time, by whoever owns the GCP project):
  `gcloud kms keyrings create`, `gcloud kms keys create`, and
  `gcloud kms keys add-iam-policy-binding` snippets.
- **Per-repo setup:**
  `git vault install --provider gcpkms --key-resource-id projects/.../cryptoKeys/...`
- **Per-developer setup:** `git vault login`, what success/failure look
  like, and the `gcloud auth application-default login` fallback.
- **Troubleshooting:** IAM-permission-denied and malformed-resource-ID
  cases (see Error handling below).

## Error handling

- Missing/invalid ADC → the verify-and-instruct message from `login`,
  and the same friendly message (not a raw gRPC/API error) if
  `encrypt`/`decrypt`/`clean`/`smudge` hit it directly without `login`
  having been run first.
- IAM permission denied on the KMS key → surfaced as-is from the GCP API
  (it already names the exact missing IAM permission); git-vault doesn't
  reinterpret it.
- Malformed `--key-resource-id` → caught at `install` time by the same
  round trip `login` uses, so a typo'd resource path fails fast instead
  of surfacing at first commit.

## Testing

- `gcpkms.Provider` unit-tested against a fake/mock KMS — sops's
  `gcpkms.MasterKey` supports injecting a `grpcConn`/`clientOpts` for
  exactly this, the same pattern sops's own tests use. No real GCP
  project involved.
- `vaultForProvider`/`install`/`login`/`rotate` CLI tests use that fake
  provider the same way existing tests fake `local`/`passphrase`.
- No integration test against real GCP infrastructure — out of scope.
