# Azure Key Vault provider (git-vault's third cloud KMS provider)

## Purpose

`gcpkms` (docs/superpowers/specs/2026-07-11-gcpkms-provider-design.md) proved
the pattern: a thin `keyservice.Provider` wrapping a sops KMS `MasterKey`,
authorized through whatever ambient cloud credentials are already active, with
no git-vault-operated service in the loop. This spec adds `azurekms`: Azure Key
Vault, authorized through the Azure SDK's `DefaultAzureCredential` chain (env
vars, workload identity, managed identity, or — for local/team use — the `az`
CLI's cached login from `az login`). This closes the README's "Azure ... on
the roadmap" line.

## Why Azure Key Vault, and why `DefaultAzureCredential`

Same rationale as gcpkms: sops already vendors `github.com/getsops/sops/v3/azkv`,
a `MasterKey` backed by `azure-sdk-for-go/sdk/azidentity` + `.../azkeys`,
already a transitive dependency via the pinned sops version. No new external
dependency, no git-vault-operated key server — Azure RBAC/access policy on the
Key Vault key is the only access control.

`DefaultAzureCredential` tries, in order: environment variables, workload
identity, managed identity, then the `az`/`azd`/PowerShell CLIs' cached
logins. For an interactive developer machine this bottoms out at the `az` CLI,
so `az login` is git-vault's analogue of `gcloud auth application-default
login` — a single command, no prior profile setup, comparable to GCP's case
and simpler than AWS's `aws configure sso` + `aws sso login` two-step.

## Key identifier: version required, no auto-fetch

sops's `azkv.NewMasterKeyFromURL` accepts a Key Vault key URL with an optional
version segment (`https://vault.../keys/name` or `.../keys/name/version`); if
the version is omitted, it does a live `GetKey` call to resolve "latest"
before the URL can be used at all. gcpkms's resource ID has no such
auto-resolution — it's fully qualified with no hidden network call.

`azurekms` follows gcpkms's shape: `--key-resource-id` must be the full URL
including version
(`https://<vault>.vault.azure.net/keys/<name>/<version>`). The provider
parses this itself and constructs `azkv.NewMasterKey(vaultURL, name, version)`
directly (not `NewMasterKeyFromURL`), so every Encrypt/Decrypt is exactly one
network round trip, never two, and a missing version is a validation error at
`install` time rather than a surprise background fetch. `git vault install`
prints the fully-qualified URL (from the Key Vault key's own "Key
Identifier") so there's a copy-pasteable value with a version already in it.

## Non-goals

- **No admin-bootstrap command.** Creating the Key Vault and key, and
  granting the `Key Vault Crypto User` role (or an access policy with
  wrap/unwrap permissions), is a rare, high-privilege action performed by
  whoever already owns the Azure subscription/resource group. It ships as
  documented `az` CLI snippets in docs/azurekms-provider.md, not a new
  git-vault subcommand.
- **No support for version-less URLs.** See above — always required,
  consistent with gcpkms's fully-qualified resource ID.
- **No shelling out to `az` except as the login fallback.** Consistent with
  using sops as a library, `git vault login`/`install` never exec `az` for
  Encrypt/Decrypt — only `login`'s fix-it path execs `az login` itself, and
  only with explicit confirmation (or `auto_login: true`), exactly like
  gcpkms's `gcloud` case.
- **Not a bulletproof credential-error classifier**, but close enough to be
  useful: `DefaultAzureCredential` fails with a fixed, stable message prefix
  ("`DefaultAzureCredential: failed to acquire a token.`") when *every*
  credential source in its chain fails, regardless of which sources were
  tried or why each one individually failed. That prefix is what
  `azurekms.ErrNoCredentials` matches on — verified empirically by running
  `DefaultAzureCredential` with zero Azure credentials configured (see
  Error handling below for the full observed message). Anything else (IAM/RBAC
  denial, malformed vault URL, wrong key name) passes through unchanged.

## Architecture

```
git vault install --provider azurekms \
    --key-resource-id https://<vault>.vault.azure.net/keys/<name>/<version>
  → .git-vault.yaml: {provider: azurekms, key_resource_id: "https://..."}
  → validates the URL immediately via the same round trip login uses

git vault login
  → attempts a harmless encrypt/decrypt round trip against the configured
    key, using whatever DefaultAzureCredential currently resolves
  → success: "Azure Key Vault round trip succeeded — this machine is
    authorized."
  → failure, no credential in the chain succeeded (errors.Is on
    azurekms.ErrNoCredentials) and `az` is on PATH: offers to run
    `az login` (confirmation required, unless auto_login), then retries
    the round trip once
  → failure, anything else: surfaces the wrapped Azure error as-is

encrypt / decrypt / clean / smudge
  → internal/keyservice/azurekms.Provider wraps sops's azkv.MasterKey
  → Encrypt(ctx, keyID, plaintext):
      parse keyID → azkv.NewMasterKey(vaultURL, name, version) → EncryptContext → EncryptedDataKey()
  → Decrypt(ctx, keyID, ciphertext):
      parse keyID → azkv.NewMasterKey(vaultURL, name, version) → SetEncryptedDataKey → DecryptContext
  → keyID is the Key Vault key URL, carried opaquely as "azurekms:<url>"
    through the same age-recipient convention gcpkms/awskms/local/passphrase
    already use — no changes to internal/vault or the sops tree format
```

## Rotation (`git vault rotate`)

Azure Key Vault key rotation (whether via its built-in rotation policy or a
manual `az keyvault key rotate`) is passive, like GCP's: rotating creates a
new key version but never disables the old one, so already-committed
ciphertext keeps decrypting under whichever version wrapped it. `rotate`
closes the same gap it does for gcpkms — re-sealing every tracked file forces
a fresh Encrypt call.

There's one wrinkle: unlike GCP's resource ID (which never encodes a version),
Azure's URL *is* pinned to a specific version. Rotating the underlying key in
Azure produces a new version, but the version baked into `.git-vault.yaml`'s
`key_resource_id` doesn't automatically follow it — `git vault rotate` for
`azurekms` must first re-resolve the key's current version (one `GetKey`
call), rewrite `key_resource_id` to point at it, and *then* re-seal every
file so each one's Encrypt call actually lands on the new version:

```go
case azurekms.Name:
    // Unlike gcpkms's resource ID, the Azure key URL is pinned to a
    // version. Re-resolve to the key's current version first and persist
    // it, so re-sealing (below) actually moves files onto the new
    // version instead of re-encrypting under the same old one.
    resolved, err := azurekms.CurrentVersionURL(cmd.Context(), cfg.KeyResourceID)
    ...
    cfg.KeyResourceID = resolved
    newVault, newRecipients, err = vaultForProvider(cfg)
    oldVault = newVault
    // cfg is saved via config.Save after the re-seal loop succeeds, same
    // place install/migrate already persist it.
```

`azurekms.CurrentVersionURL` is a small provider-level helper: parse the vault
URL + key name out of the existing `key_resource_id`, call `azkeys.Client.GetKey`
with an empty version (Key Vault's convention for "latest"), and rebuild the
URL with the resolved version. The follow-up message mirrors gcpkms's: *"Old
Key Vault key versions are still enabled to decrypt anything not yet
migrated, including committed history. Once every commit that matters has
been rotated, disable the old version in Azure to complete the rotation."*

## Components touched

- **New: `internal/keyservice/azurekms/azurekms.go`.** A `Provider`
  implementing `Name()`, `Encrypt`, `Decrypt` by wrapping sops's
  `azkv.MasterKey`. Also exports `ErrNoCredentials`, a `friendlyLoginErr`
  matching the `DefaultAzureCredential` prefix (see Error handling), and
  `CurrentVersionURL` for `rotate`. No new external dependency — `azkv` is
  already pulled in transitively by the pinned sops version.
- **`internal/cli/vault.go`:** new `newAzureKMSVault(cfg)` builder and a
  `case azurekms.Name` in `vaultForProvider`'s switch, same shape as
  `newGCPKMSVault`.
- **`internal/cli/install.go`:** accept `azurekms` in `--provider`,
  reuse the existing `--key-resource-id` flag (already generic across
  gcpkms/azurekms), validate via the same round trip `login` uses.
- **`internal/cli/login.go`:** add sibling `verifyAzureKMSRoundTrip`/
  `attemptAzLogin` functions (same shape as `verifyGCPKMSRoundTrip`/
  `attemptGcloudLogin`), and change the command's provider check from
  `cfg.Provider != gcpkms.Name` to a switch over `{gcpkms.Name,
  azurekms.Name}` so each dispatches to its own verify/offer-fix pair;
  anything else keeps today's "does not use git vault login" error.
- **`internal/cli/rotate.go`:** add `case azurekms.Name` per the Rotation
  section above — the one provider-specific step beyond gcpkms's pattern is
  re-resolving and persisting the current key version before re-sealing.
- **`internal/cli/migrate.go`:** no changes needed beyond accepting
  `azurekms` as a valid `--provider` target (already generic:
  `vaultForProvider` handles construction, and the existing
  resolved-recipient-string comparison already generalizes to any provider
  whose identity is `provider + key ID`, not just gcpkms).
- **New: `docs/azurekms-provider.md`.** User-facing setup guide (see below)
  — content is written during implementation, not in this spec.
- **`README.md`:** add a link to `docs/azurekms-provider.md`, update the
  "Azure ... on the roadmap" line since this closes that gap.

## `docs/azurekms-provider.md` contents (to be written)

- **Admin bootstrap** (one-time, by whoever owns the Azure subscription):
  `az keyvault create`, `az keyvault key create`, and
  `az keyvault set-policy` / `az role assignment create` (Key Vault Crypto
  User) snippets, plus how to read the key's fully-qualified URL (`az
  keyvault key show --query key.kid`).
- **Per-repo setup:**
  `git vault install --provider azurekms --key-resource-id https://.../keys/.../<version>`.
- **Per-developer setup:** `git vault login`, what success/failure look
  like, and the `az login` fallback.
- **Rotation:** what `git vault rotate` does for this provider (including
  the version-re-resolution wrinkle) and the `az keyvault key set-attributes
  --enabled false` command to run against the old version once every
  relevant commit has been rotated.
- **Troubleshooting:** RBAC/access-policy-denied and malformed-URL cases
  (see Error handling below).

## Error handling

- Missing/invalid credentials → the verify-and-instruct message from
  `login`, and the same friendly message if `encrypt`/`decrypt`/`clean`/
  `smudge` hit it directly without `login` having been run first. The
  observed full message when no credential source succeeds (confirmed by
  running `DefaultAzureCredential` locally with no Azure environment set
  up) is:

  ```
  DefaultAzureCredential: failed to acquire a token.
  Attempted credentials:
  	EnvironmentCredential: missing environment variable AZURE_TENANT_ID
  	WorkloadIdentityCredential: no client ID specified. Check pod configuration or set ClientID in the options
  	ManagedIdentityCredential: managed identity timed out. ...
  	AzureCLICredential: executable not found on path
  	AzureDeveloperCLICredential: executable not found on path
  	AzurePowerShellCredential: executable not found on path
  ```

  `friendlyLoginErr` matches on the stable `"DefaultAzureCredential: failed to
  acquire a token"` prefix (present regardless of which sub-credentials were
  attempted) and rewrites it to `ErrNoCredentials`, exactly like gcpkms's
  substring match on `"could not find default credentials"`. This call can
  take a few seconds when a managed-identity source times out — same
  characteristic AWS's IMDS timeout has, not something git-vault can avoid
  without reimplementing Azure's chain.
- RBAC/access-policy denied on the Key Vault key → surfaced as-is from the
  Azure API (it already names the missing permission); git-vault doesn't
  reinterpret it.
- Malformed `--key-resource-id` (wrong shape, or missing version) → caught
  at `install` time by the same round trip `login` uses, so a typo'd URL
  fails fast instead of surfacing at first commit.

## Testing

- `azurekms.Provider` unit-tested against a fake Key Vault: an
  `httptest.Server` handling the `encrypt`/`decrypt` REST endpoints
  `azkeys.Client` calls, injected via `azkv.ClientOptions.ApplyToMasterKey`
  (its `azcore.ClientOptions.Transport` field), plus a fake
  `azcore.TokenCredential` (returns a fixed dummy token, no real Azure
  tenant) injected via `azkv.TokenCredential.ApplyToMasterKey` — the exact
  same injection pattern gcpkms's `SetClientOptionsForTesting` uses, just
  over HTTP instead of gRPC. Package name: `azurekmstest`, mirroring
  `gcpkmstest`.
- `friendlyLoginErr` unit-tested directly against the exact message text
  captured in Error handling above (both the "no credentials" case and a
  pass-through case), the same way `TestFriendlyLoginErr_*` covers gcpkms.
- `vaultForProvider`/`install`/`login`/`rotate`/`migrate` CLI tests use the
  fake provider the same way existing tests fake `local`/`passphrase`/
  `gcpkms`. The rotate test should assert `key_resource_id` in
  `.git-vault.yaml` actually changes to a new version string, not just that
  the command exits zero — that's the provider-specific behavior this spec
  adds on top of gcpkms's rotate pattern.
- No integration test against a real Azure tenant — out of scope.
</content>
