# vault: real sops integration + local provider

Date: 2026-07-11
Status: approved

## Purpose

The project scaffold (`2026-07-10-git-vault-scaffold-design.md`) established
package boundaries but left the actual crypto path stubbed:
`internal/vault.Seal`/`Open` return `ErrNotImplemented`, and the only
registered `Provider` (`StubProvider`) always errors. This spec implements
the real thing: `internal/vault` calls `sops-as-a-library` against
git-vault's own keyservice, dispatched to a new, real, shippable `local`
key provider. This is the first point at which the full pipeline
(CLI → vault → keyservice → provider) can actually encrypt and decrypt a
file.

## Non-goals

- Wiring `clean`/`smudge`/`encrypt`/`decrypt`/`install` CLI commands to
  the new `Vault` API. That's a separate follow-up (this spec only builds
  `internal/vault` and the `local` provider).
- A real SSO provider or `login` command. `local` is single-machine only;
  team key distribution is a later provider's problem.
- Shamir secret sharing / multiple key groups. Every file gets exactly one
  key group.

## Keyservice wiring: in-process, not gRPC

sops's keyservice protocol is designed for remote key services (a gRPC
`KeyServiceServer`), but the library also ships
`keyservice.NewCustomLocalClient(server)`, which wraps any
`KeyServiceServer` in-process with zero networking — the client's
`Encrypt`/`Decrypt` call straight into the server's methods, no socket, no
listener, no serialization. Since `internal/keyservice.Server` already
implements `sopskeyservice.KeyServiceServer`, and every git-vault
subcommand (`clean`, `smudge`, `encrypt`, `decrypt`) runs the CLI in a
single process, there is no cross-process caller to justify a real gRPC
listener.

`Vault` is constructed with `*keyservice.Server` directly and wraps it once
via `NewCustomLocalClient`. This replaces the current stub's
`KeyserviceAddr string` field entirely — there is no address, no unix
socket, no server lifecycle to start or clean up.

## Vault API

```go
package vault

type Vault struct {
    keyservices []sopskeyservice.KeyServiceClient // wraps *keyservice.Server in-process
}

func New(server *keyservice.Server) *Vault

// Seal encrypts the file at path in place, creating a fresh sops tree
// keyed to recipients (opaque "<provider>:<key-id>" strings).
func (v *Vault) Seal(path string, recipients []string) error

// Open decrypts the file at path in place.
func (v *Vault) Open(path string) error

// SealStream/OpenStream are the same operations against io.Reader/io.Writer
// instead of a file path, for git's clean/smudge filters (which receive
// content on stdin/stdout, not a real file) — built now, wired to the CLI
// in a later change.
func (v *Vault) SealStream(w io.Writer, r io.Reader, format Format, recipients []string) error
func (v *Vault) OpenStream(w io.Writer, r io.Reader, format Format) error
```

`Vault` never imports `internal/keyservice`'s `Provider`/`Registry` types
or anything provider-specific — only the `*keyservice.Server` it's given
and sops. Recipients are opaque strings supplied by the caller. The CLI
layer (not built in this spec, but the shape follow-up work will use) is
the only place that knows about both `internal/config` (which provider is
configured) and `internal/keyservice` (the provider registry) and bridges
them into a recipient string before calling `Seal`.

### Seal flow

1. Pick a `Store` for `path` by extension (see Format handling).
2. Build a fresh `sops.Tree` with one `KeyGroup`: one
   `age.MasterKey{Recipient: r}` per entry in `recipients`. (sops never
   validates this string as a real age key unless the real age crypto path
   runs, which it doesn't here — see "Why the age key type" below.)
3. `tree.GenerateDataKeyWithKeyServices(v.keyservices)`.
4. `tree.Metadata.UpdateMasterKeysWithKeyServices(dataKey, v.keyservices)`
   — this is what actually calls into `keyservice.Server.Encrypt`, which
   dispatches to the `local` provider.
5. `common.EncryptTree(...)` encrypts the tree's values with the data key.
6. `store.EmitEncryptedFile(tree)`, write result to `path` (or `w` for the
   stream variant).

### Open flow

1. Pick the `Store` the same way.
2. `store.LoadEncryptedFile(fileBytes)` → `sops.Tree`.
3. `common.DecryptTree(...)` → calls `Metadata.GetDataKeyWithKeyServices`,
   which calls `keyservice.Server.Decrypt`, dispatching to the provider.
4. `store.EmitPlainFile(tree.Branches)`, write result to `path` (or `w`).

### Why the age key type carries an opaque string safely

Confirmed by reading `github.com/getsops/sops/v3`:

- `age.MasterKeyFromRecipient` (which validates bech32 age format) is only
  called when *constructing* a key from a real recipient string via that
  specific constructor — git-vault constructs `age.MasterKey{Recipient: r}`
  directly as a struct literal, skipping validation.
- On load, `stores.agekey.toInternal()` also builds `&age.MasterKey{...}`
  directly from the file's metadata with no parsing.
- `keyservice.KeyFromMasterKey` (called for every key, every provider, on
  every encrypt/decrypt) reads `mk.Recipient` as a plain string with no
  validation, wrapping it into the wire `AgeKey{Recipient: ...}`.
- The only code path that ever calls `parseRecipient` (real bech32
  validation) is `age.MasterKey.Encrypt`/`Decrypt` — sops's own *local*
  age crypto implementation, which is never invoked because git-vault's
  keyservice intercepts every age-shaped key before it gets there.

So `"local:age1qy8..."` round-trips through sops's metadata and wire
format as an inert string; only git-vault's own `keyservice.Server` (and,
inside it, the `local` provider) ever interprets it.

## Format handling

- `.yaml`/`.yml` → sops's YAML store (`cmd/sops/common.StoreForFormat`
  with `formats.Yaml`) — only leaf values are ciphertext, keys/structure
  stay readable.
- `.json` → JSON store, same structure-preserving behavior.
- `.env` and `.env.<anything>` (e.g. `.env.production`, `.env.local`) →
  dotenv store. sops's own `formats.FormatForPath` only matches an exact
  `.env` suffix, so git-vault adds one local helper (`isDotenvPath`) that
  also matches a `.env.` segment before calling
  `common.StoreForFormat(formats.Dotenv, ...)` directly (skipping
  `DefaultStoreForPath`, which would misdetect `.env.production` as
  binary).
- Anything else → binary store (sops's whole-file opaque-blob format) —
  same fallback stock `sops` uses.

## Local provider

New package, e.g. `internal/keyservice/local`, registered under the name
`"local"`.

- On first use (no existing identity), generates an X25519 age identity
  via `filippo.io/age` — already a transitive dependency of sops, no new
  module added.
- Private key stored at `~/.cache/git-vault/local/identity.txt`, mode
  `0600`, analogous to `internal/session`'s cache directory convention.
- The identity's bech32 public key *is* the key-id used in recipient
  strings: `"local:age1qy8..."`.
- `Provider.Encrypt`/`Decrypt` perform real age encryption/decryption of
  the sops data key (a ~32-byte blob) against that identity, using
  `filippo.io/age` directly — reusing audited crypto rather than
  hand-rolling AES.
- Scope: single-machine only. This is a legitimate, usable first provider
  for a solo dev or single-machine repo — not a team key-sharing solution.
  It also serves as `internal/vault`'s own integration-test fixture, so
  the crypto path is proven correct without needing a real SSO provider
  built first.

## Error handling

`Seal`/`Open` return plain Go errors, unwrapped from sops's
`cli.ExitError` (`common.NewExitError` wraps errors for the sops CLI's own
exit-code handling, which git-vault doesn't use) — no swallowed errors,
consistent with the project's fail-closed philosophy.

## Testing

- `internal/vault`: a round-trip test per format (YAML, JSON, `.env.local`,
  binary) — seal then open through the `local` provider, assert output
  equals input. A golden-file assertion for YAML/JSON specifically checks
  that map keys remain plaintext while values do not.
- `internal/keyservice/local`: identity-generation-on-first-use test, and
  an encrypt/decrypt round-trip test against a fixed data key.
