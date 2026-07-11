# `local` provider: post-quantum identity type

Date: 2026-07-12
Status: approved

## Purpose

Of git-vault's four provider paths, three already only ever wrap the sops
data key with a symmetric operation (`passphrase`'s scrypt-derived key,
`gcpkms`'s `GOOGLE_SYMMETRIC_ENCRYPTION`) or aren't built yet
(`awskms`/`azurekms`). Symmetric ciphers lose only half their effective key
strength to Grover's algorithm (AES-256 stays at a 128-bit security level),
so none of those are an actual quantum exposure.

`local` — the **default** provider (`install.go`'s `--provider` flag
defaults to it) — is the one real exposure: it wraps the data key with plain
age `X25519Identity` (ECDH over Curve25519), which a sufficiently large
cryptographically-relevant quantum computer breaks via Shor's algorithm.
Ciphertext committed today ("harvest now, decrypt later") would be exposed
retroactively.

This is general hygiene, not a response to a specific deadline or compliance
ask, so the fix should be the smallest change that removes the exposure for
every current and future `local` user, using what already exists rather than
adding new machinery:

- `filippo.io/age v1.3.1` — already the exact version pinned in `go.mod` —
  ships `HybridIdentity`/`HybridRecipient` (`pq.go`): a hybrid ML-KEM-768 +
  X25519 KEM (`age1pq...` / `AGE-SECRET-KEY-PQ-...`), NIST-standardized and
  hybrid (breaking either the classical or the PQ half alone isn't enough).
  No new dependency.
- `git vault rotate` (`internal/cli/rotate.go`) already generates a fresh
  identity, re-seals every tracked file under it, and keeps the old identity
  around read-only for anything not yet re-sealed. That is exactly the
  migration this needs — reused as-is, not extended.

## Non-goals

- **Any change to `internal/keyservice/provider.go`, `internal/cli/rotate.go`,
  `internal/vault`, or `.git-vault.yaml`'s schema.** `Provider.Encrypt`/
  `Decrypt` already treat `keyID` as opaque; `rotate` already dispatches to
  `provider.Rotate()` generically. This spec is entirely internal to
  `internal/keyservice/local/local.go`.
- **Forcing existing users to migrate.** Old X25519 identities keep
  decrypting their own ciphertext forever (same guarantee `rotate` already
  gives for ordinary key rotation) — migration is one already-familiar
  `git vault rotate` call, never mandatory, never automatic.
- **`passphrase` or `gcpkms`.** Both already wrap with a symmetric operation;
  neither has a quantum exposure to fix. `awskms`/`azurekms` aren't built
  yet, so there's nothing to retrofit — their eventual design docs should
  just default to a symmetric key spec (`SYMMETRIC_DEFAULT` /
  `GOOGLE_SYMMETRIC_ENCRYPTION`-equivalent), noted there, not here.
- **Any new CLI flag, config field, or provider name** (e.g. an opt-in `--pq`
  flag, or a separate `local-pq` provider). Considered and rejected: an
  opt-in default doesn't fix the actual exposure since most installs
  wouldn't ask for it, and a parallel provider duplicates the identity-list/
  rotate/decrypt-match logic that already exists in `local.go` for no
  benefit — the goal is fixing the default, not adding a second one people
  have to know to pick.

## `local` provider

`internal/keyservice/local/local.go`:

- **Identity list type widens** from `[]*age.X25519Identity` to
  `[]age.Identity`, since a repo can now legitimately hold a mix: older
  X25519 identities (never removed) plus newer `HybridIdentity` ones. The
  `identities()` type-check loop still rejects anything that's neither
  `*age.X25519Identity` nor `*age.HybridIdentity` — same forward-compat
  guard as today, just widened to the two current concrete types.
- **Fresh installs** (`identities()`, no `identities` file and no legacy
  `identity.txt` to migrate): generate `age.GenerateHybridIdentity()`
  instead of `age.GenerateX25519Identity()`. Every new `local` install is
  PQ-safe from its first commit, no extra step required.
- **`Rotate()`**: generates `age.GenerateHybridIdentity()` instead of
  `age.GenerateX25519Identity()`, appended exactly as today (`id.String()`
  writes the `AGE-SECRET-KEY-PQ-...` form on its own line — no format
  change). This is the existing-user migration path: run
  `git vault rotate` once, every tracked file gets re-sealed to the new
  hybrid recipient, and the old X25519 identity is retained for anything not
  yet re-sealed (including committed history) — identical framing to
  today's ordinary key-rotation story.
- **`Recipient()` / `Decrypt()`**: `X25519Identity.Recipient()` and
  `HybridIdentity.Recipient()` return different concrete types (age's
  `Identity` interface only requires `Unwrap`, not `Recipient`), so getting
  a recipient string generically needs a small private type switch, e.g.:

  ```go
  func recipientString(id age.Identity) (string, error) {
      switch v := id.(type) {
      case *age.X25519Identity:
          return v.Recipient().String(), nil
      case *age.HybridIdentity:
          return v.Recipient().String(), nil
      default:
          return "", fmt.Errorf("local: unsupported identity type %T", id)
      }
  }
  ```

  `Recipient()` (newest identity) and `Decrypt()`'s match-by-`keyID` loop
  both call this instead of `.Recipient().String()` directly. `Decrypt`'s
  `match` variable becomes `age.Identity`; the final `age.Decrypt(ar,
  match)` call is unaffected since it already accepts the `age.Identity`
  interface.
- **`Encrypt()`**: replace the hardcoded `age.ParseX25519Recipient(keyID)`
  with `age.ParseRecipients(strings.NewReader(keyID))`, taking the single
  result — `ParseRecipients` is exported by the age library specifically to
  dispatch on the `age1`/`age1pq` prefix, so this reuses it rather than
  hand-rolling the same prefix check. Errors if parsing fails or yields a
  count other than 1 (a single recipient string should never parse to more
  than one recipient).
- **`migrateLegacyIdentity()`**: unchanged — it only copies raw bytes: a
  pre-existing `identity.txt` is always X25519 (predates `HybridIdentity`
  entirely), and `ParseIdentities` already parses whichever concrete type
  each line encodes.

## Error handling

- `identities()` encountering an identity type outside
  `{X25519Identity, HybridIdentity}`: same `"unsupported identity type %T"`
  error shape as today, widened to the two accepted types.
- `Encrypt` given a `keyID` that fails to parse as a recipient, or parses to
  a count other than 1: wrapped error naming the offending `keyID`, same
  style as the existing `"local: parse recipient %q: %w"`.
- `Decrypt` with no stored identity matching `keyID`: unchanged —
  `"local: no stored identity matches recipient %q"`.
- No change to `Rotate()`'s or `identities()`'s existing file I/O error
  handling (create dir, write, append, close) — only the identity type
  generated changes, not the persistence logic around it.

## Testing

- Fresh `Provider` (no `identities` file, no legacy `identity.txt`):
  `Recipient()` returns an `age1pq...` string.
- A `Provider` pointed at a pre-existing X25519-only identity file: existing
  Encrypt/Decrypt round-trip still passes unmodified (no forced migration,
  no format change for old-only repos).
- After `Rotate()` on such a provider: `Recipient()` now returns the new
  `age1pq...` string; ciphertext produced under the old X25519 recipient
  still decrypts (old identity retained); new `Encrypt` calls target the new
  hybrid recipient.
- Mixed identity file (one X25519 line + one Hybrid line, constructed
  directly rather than via two `Rotate()` calls) round-trips both.
- `identities()` rejects an unrelated `age.Identity` implementation (if one
  is easy to construct in-test) with the widened type-check error.
