# HashiCorp Vault Transit provider (git-vault's fourth KMS-style provider)

## Purpose

gcpkms, awskms, and azurekms proved the pattern: a thin `keyservice.Provider`
wrapping a sops KMS `MasterKey`, authorized through whatever ambient
credentials are already active, with no git-vault-operated service in the
loop. This spec adds a HashiCorp Vault provider (`--provider vault`) backed by
Vault's Transit secrets engine, for teams whose shared secret material lives
in a self-hosted or HCP Vault cluster rather than a cloud KMS.

## Why Vault Transit

sops already vendors `github.com/getsops/sops/v3/hcvault`, a `MasterKey`
backed by `github.com/hashicorp/vault/api` — already a transitive dependency
via the pinned sops version (confirmed via `go mod why
github.com/hashicorp/vault/api`; only `go mod tidy` is needed to promote it
from indirect to direct). No new external dependency, no git-vault-operated
key server — Vault's own ACL policy on the Transit key is the only access
control.

Unlike the cloud providers' SDK credential chains, Vault auth is a plain
bearer token: `sops`'s `hcvault` package resolves it from an explicit value,
else the `VAULT_TOKEN` env var, else `~/.vault-token` (the file the `vault`
CLI itself writes on `vault login`). So `vault login` is git-vault's analogue
of `az login`/`gcloud auth application-default login` — except Vault supports
many auth methods (token, userpass, LDAP, OIDC, GitHub, AppRole...) that vary
per org, so `vault login` with no arguments only covers the default token
method; anyone on another method runs their own `vault login -method=...`
first.

## Key identifier: reuse sops's own URI parser, no hand-rolled regex

gcpkms/awskms/azurekms each hand-parse `--key-resource-id` into their
provider's pieces (a resource path, an ARN, a Key Vault URL). sops's
`hcvault` package already ships `NewMasterKeyFromURI(uri string) (*MasterKey,
error)`, which parses a full Transit key URL
(`https://vault.example.com:8200/v1/<enginePath>/keys/<keyName>`) into
`VaultAddress`/`EnginePath`/`KeyName` directly. The Vault provider calls this
verbatim instead of writing its own parser — `--key-resource-id` for
`--provider vault` is exactly that URL, unchanged.

Unlike Azure's Key Vault URL, this URL never encodes a version: Vault Transit
encryption always uses the key's current version, and the resulting
ciphertext string embeds which version wrapped it (Vault decrypts using
whatever version the ciphertext names, up to the key's configured
`min_decryption_version`). So there's no "missing version" validation case
and no version-pinning wrinkle to carry through rotate — this key identifier
behaves like GCP's resource ID, not like Azure's.

## Non-goals

- **No admin-bootstrap command.** Enabling the Transit secrets engine
  (`vault secrets enable transit`), creating the key (`vault write -f
  transit/keys/<name>`), and writing an ACL policy granting
  `update` on `transit/encrypt/<name>` and `transit/decrypt/<name>` is a
  rare, high-privilege action performed by whoever administers the Vault
  cluster. It ships as documented `vault` CLI snippets in
  `docs/vault-provider.md`, not a new git-vault subcommand.
- **Not a bulletproof credential classifier.** Vault returns the same HTTP
  403 `permission denied` for a missing token, an invalid token, an expired
  token, and a validly-authenticated token that simply lacks the right ACL
  policy — there is no distinct signal for "you have no credentials" the way
  Azure's `DefaultAzureCredential` failure message provides. The provider
  classifies any 403 as `ErrNoValidToken` (same "run the login step and
  retry" fix applies to all four causes) and does not attempt to distinguish
  further; anything else (network error, malformed URL, sealed vault) passes
  through unchanged.
- **Transit only.** No support for the KV secrets engine or any other Vault
  engine — Transit's `encrypt`/`decrypt` endpoints are the direct analogue of
  the cloud providers' envelope-encryption KMS calls, and it's what sops's
  `hcvault` package targets.
- **`vault login` runs with no arguments.** This only performs the default
  token auth method (interactively prompts for a token to paste). Org-specific
  methods (OIDC, LDAP, GitHub, AppRole) need to be run manually
  (`vault login -method=oidc`, etc.) — the auto-exec is a convenience for the
  common case, not a full wrapper over every Vault auth method.
- **Allowlist pinning is best-effort, process-wide, not concurrency-safe.**
  See Architecture below — acceptable for a single sequential CLI invocation,
  not something a hypothetical concurrent daemon could rely on.

## Architecture

```
git vault install --provider vault \
    --key-resource-id https://vault.example.com:8200/v1/transit/keys/<name>
  → .git-vault.yaml: {provider: vault, key_resource_id: "https://..."}
  → validates the URL immediately via the same round trip login uses

git vault login
  → attempts a harmless encrypt/decrypt round trip against the configured
    key, using whatever token VAULT_TOKEN/~/.vault-token currently resolves
  → success: "Vault Transit round trip succeeded — this machine is
    authorized."
  → failure, permission denied (errors.Is on hcvault.ErrNoValidToken) and
    `vault` is on PATH: offers to run `vault login` (confirmation required,
    unless auto_login), then retries the round trip once
  → failure, anything else: surfaces the wrapped Vault error as-is

encrypt / decrypt / clean / smudge
  → internal/keyservice/hcvault.Provider wraps sops's hcvault.MasterKey
  → Encrypt(ctx, keyID, plaintext):
      hcvault.NewMasterKeyFromURI(keyID) → pin SOPS_HC_VAULT_ALLOWLIST to
      the parsed VaultAddress → EncryptContext → EncryptedDataKey()
  → Decrypt(ctx, keyID, ciphertext):
      hcvault.NewMasterKeyFromURI(keyID) → pin allowlist → SetEncryptedDataKey
      → DecryptContext
  → keyID is the Transit key URL, carried opaquely as "vault:<url>" through
    the same age-recipient convention every other provider uses — no changes
    to internal/vault or the sops tree format
```

**Allowlist pinning.** sops's `hcvault` client refuses to talk to a Vault
address unless it's in the `SOPS_HC_VAULT_ALLOWLIST` env var — but its
default (`AllowlistDefault = AllowlistAllHosts`) already allows every
address, so unset it's a no-op, not a blocker. To avoid depending on the
user's shell environment for a safety check, `hcvault.Provider` sets
`SOPS_HC_VAULT_ALLOWLIST` to exactly the configured key's `VaultAddress`
(via `os.Setenv`) immediately before each Encrypt/Decrypt call, so sops's
client only ever talks to the one Vault address `--key-resource-id` names —
defense in depth against env var pollution, not against a deliberately
misconfigured `--key-resource-id`. `os.Setenv` is process-global; fine for
git-vault's one-command-at-a-time CLI usage, not thread-safe if that ever
changes.

## Rotation (`git vault rotate`)

Vault Transit key rotation (`vault write -f transit/keys/<name>/rotate`) is
passive, like GCP's and AWS's: it creates a new key version but (by default)
never disables old ones — `min_decryption_version` controls how far back
decryption still works, defaulting to 1 (all versions). `rotate` closes the
same gap: re-sealing every tracked file forces a fresh Encrypt call, which
Vault always services with the key's current version, moving every file's
wrapped data key off whatever version it was on before. There's no version
encoded in `--key-resource-id` to re-resolve (see Key identifier above), so
this is exactly awskms's shape in `rotate.go` — re-seal, no config rewrite.

## Components touched

- **New: `internal/keyservice/hcvault/hcvault.go`.** A `Provider`
  implementing `Name()` (`"vault"`), `Encrypt`, `Decrypt` by wrapping sops's
  `hcvault.MasterKey`, constructed via `hcvault.NewMasterKeyFromURI`. Also
  exports `ErrNoValidToken` and a `friendlyLoginErr` that classifies a Vault
  API 403 (`*vaultapi.ResponseError` with `StatusCode == 403`) into it, and
  `SetTestOverridesForTesting(token string, hc *http.Client) (restore
  func())` for injecting a fake token/HTTP transport in tests (mirrors
  azurekms's `SetTestOverridesForTesting` shape). No new external dependency
  — `hashicorp/vault/api` is already pulled in transitively by the pinned
  sops version; `go mod tidy` promotes it to a direct require.
- **`internal/cli/vault.go`:** new `newVaultKMSVault(cfg)` builder and a
  `case hcvault.Name` in `vaultForProvider`'s switch, same shape as
  `newAzureKMSVault`.
- **`internal/cli/install.go`:** accept `vault` in `--provider`, reuse the
  existing `--key-resource-id` flag (add `hcvault.Name` to the
  gcpkms/awskms/azurekms "resource ID required" condition and the flag help
  text), validate via the same round trip `login` uses.
- **`internal/cli/login.go`:** add sibling `verifyVaultRoundTrip`/
  `attemptVaultLogin` functions (same shape as `verifyAzureKMSRoundTrip`/
  `attemptAzLogin`, running `vault login` with no arguments), add
  `case hcvault.Name` to the provider switch.
- **`internal/cli/rotate.go`:** add `case hcvault.Name` — identical shape to
  `awskms.Name`'s case (re-seal via `vaultForProvider(cfg)`, no config
  rewrite), with a follow-up message pointing at
  `vault write -f transit/keys/<name>/rotate` and `min_decryption_version`
  to retire old versions once migration is complete.
- **`internal/cli/migrate.go`:** no changes needed — already generic over
  `vaultForProvider`.
- **New: `docs/vault-provider.md`.** User-facing setup guide (content
  written during implementation, not in this spec) covering: admin
  bootstrap (`vault secrets enable transit`, `vault write -f
  transit/keys/<name>`, an ACL policy snippet), per-repo `install`,
  per-developer `login` (including the `vault login` fallback and a note on
  non-token auth methods), rotation, and troubleshooting (permission denied,
  sealed vault, malformed URL).
- **`README.md`:** add `vault` to the provider list and a
  `docs/vault-provider.md` link, alongside the existing three.

## Error handling

- Permission denied (missing, invalid, or expired token, or insufficient ACL
  policy) → classified as `ErrNoValidToken`, surfaced by `login`/`install`
  with the fix-it prompt above; the same message if `encrypt`/`decrypt`/
  `clean`/`smudge` hit it directly without `login` having been run first.
- Vault sealed, unreachable, or a malformed `--key-resource-id` → surfaced
  as-is from the Vault API/`NewMasterKeyFromURI`, no reinterpretation.
  `NewMasterKeyFromURI` rejects a URI with no scheme (comparable to
  awskms's ARN-shape validation), so a typo'd URL fails fast at `install`
  time via the same round trip `login` uses.

## Testing

- `hcvault.Provider` unit-tested against a fake Transit endpoint: an
  `httptest.Server` handling the `v1/<engine>/encrypt/<name>` and
  `v1/<engine>/decrypt/<name>` paths sops's `hcvault.MasterKey` POSTs to,
  injected via `hcvault.NewHTTPClient(hc).ApplyToMasterKey(key)` (already
  exported by sops), plus a fixed dummy token via
  `hcvault.Token(token).ApplyToMasterKey(key)` — no real Vault cluster.
  Package name: `hcvaulttest`, mirroring `azurekmstest`.
- `friendlyLoginErr` unit-tested directly against a synthetic
  `*vaultapi.ResponseError{StatusCode: 403}` and a pass-through case (e.g.
  a 500 or a network error), the same way `TestFriendlyLoginErr_*` covers
  azurekms.
- `vaultForProvider`/`install`/`login`/`rotate`/`migrate` CLI tests use the
  fake provider the same way existing tests fake `local`/`passphrase`/
  `azurekms`. The rotate test should assert the re-seal happens (old vault
  can no longer decrypt post-rotation files, matching awskms's rotate test
  shape) without asserting any `.git-vault.yaml` rewrite, since none occurs.
- No integration test against a real Vault server — out of scope (contrast:
  sops's own `hcvault` package test suite spins up a real Vault via
  `dockertest`, which this repo's test suite does not do for any provider).
