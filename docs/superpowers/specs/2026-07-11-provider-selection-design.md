# CLI: config-driven provider selection (local vs passphrase)

Date: 2026-07-11
Status: approved

## Purpose

`2026-07-11-cli-vault-wiring-design.md` wired `encrypt`/`decrypt`/`clean`/
`smudge`/`install` to a real pipeline, but hardcoded the `local` provider
(`internal/cli/vault.go`'s `newLocalVault`). A second real provider,
`internal/keyservice/passphrase`, now exists but nothing in the CLI can
reach it — `.git-vault.yaml` (`internal/config`) is written and read by
nothing. This spec wires that file up as the switch between `local` and
`passphrase`, so a repo can choose which one it uses and every command
honors that choice.

## Non-goals

- A `login`/SSO provider. `config.Config`'s `IssuerURL`/`ClientID` fields
  stay unused by this pass — they exist for that future provider, not this
  one.
- **Rotating or migrating existing ciphertext when the provider changes.**
  Re-running `install --provider=X` on a repo that already has files
  sealed under a *different* provider does not detect that, warn, or
  re-encrypt anything — it just overwrites `.git-vault.yaml`, and existing
  ciphertext becomes undecryptable under the new provider until the old
  one is switched back. Doing this safely means enumerating tracked files
  (`gitattr.Tracked` + the `trackedFiles` helper already in `status.go`),
  opening each under the *old* config, and re-sealing under the *new*
  one — a `rotate`/`migrate` command (the two are effectively the same
  operation: re-seal all tracked files under new key material) is real,
  separate follow-up work, not built here. Until it exists, switching
  providers on a repo with existing ciphertext requires manually decrypting
  everything, changing `.git-vault.yaml`, and re-encrypting.
- A third provider. Dispatch is a plain `switch` on two known names; it
  gets a third `case` when a third provider exists, not before.
- Any change to `internal/keyservice`, `internal/vault`, or the `Provider`
  interface itself. This is pure `internal/cli` wiring on top of what
  already exists.

## Architecture

`internal/cli/vault.go` gains a second builder alongside the existing
`newLocalVault`, plus a dispatcher that replaces every direct call to
`newLocalVault()` in `encrypt.go`/`decrypt.go`/`clean.go`/`smudge.go`:

```go
func newPassphraseVault() (*vault.Vault, []string, error) {
    provider := passphrase.New()
    registry := keyservice.NewRegistry()
    if err := registry.Register(provider); err != nil {
        return nil, nil, err
    }
    server := keyservice.NewServer(registry)
    return vault.New(server), []string{passphrase.Name + ":" + passphrase.KeyID}, nil
}

// newVault loads .git-vault.yaml and builds the Vault for whichever
// provider it names, replacing direct newLocalVault() calls in every
// command except install (which builds explicitly for the --provider flag
// value, since the file doesn't exist yet on first install).
func newVault() (*vault.Vault, []string, error) {
    cfg, err := loadConfig()
    if err != nil {
        return nil, nil, err
    }
    return vaultForProvider(cfg.Provider)
}

func vaultForProvider(name string) (*vault.Vault, []string, error) {
    switch name {
    case local.Name:
        return newLocalVault()
    case passphrase.Name:
        return newPassphraseVault()
    default:
        return nil, nil, fmt.Errorf("git vault: unknown provider %q in %s", name, config.DefaultFileName)
    }
}

// loadConfig wraps config.Load with a hint pointing at `install` when the
// file is simply missing, instead of surfacing a raw os.PathError.
func loadConfig() (config.Config, error) {
    cfg, err := config.Load(config.DefaultFileName)
    if err != nil {
        if os.IsNotExist(err) {
            return config.Config{}, fmt.Errorf(`git vault: no %s found, run "git vault install" first`, config.DefaultFileName)
        }
        return config.Config{}, fmt.Errorf("git vault: read %s: %w", config.DefaultFileName, err)
    }
    return cfg, nil
}
```

`newLocalVault` itself is unchanged. `vaultForProvider` is factored out
separately from `newVault` so `install` can call it directly with the
flag's value, before any config file exists.

## install

Gains a `--provider` flag (default `"local"`), validated against the same
two names via `vaultForProvider` before anything else happens:

1. `vaultForProvider(providerName)` — builds the real provider. For
   `passphrase` this reads `GIT_VAULT_PASSPHRASE` as part of building the
   `age.ScryptRecipient`/`Identity` path indirectly (see
   `passphrase.Provider`), so a missing passphrase fails install
   immediately rather than surfacing later on the first real `encrypt`.
   An unknown `--provider` value fails the same way, before touching git
   config or the filesystem.
2. Resolve the recipient to print:
   - `local`: `provider.Recipient()` as today.
   - `passphrase`: the fixed `passphrase.Name + ":" + passphrase.KeyID`.
3. Set the three `filter.git-vault.*` git config values as today.
4. `config.Save(config.DefaultFileName, config.Config{Provider: providerName})`.
5. Print the recipient and scope, as today.

Re-running `install` with the same `--provider` is idempotent, same as
before. Re-running with a *different* `--provider` overwrites
`.git-vault.yaml` — see the rotate/migrate non-goal above.

## encrypt / decrypt / clean / smudge

Each swaps its `newLocalVault()` call for `newVault()`. No other change —
`Seal`/`Open`/`SealStream`/`OpenStream` already take the same
`(*vault.Vault, []string)` shape either builder returns.

## Error handling

- Missing `.git-vault.yaml`: clear message pointing at `git vault install`
  (see `loadConfig` above), not a raw file-not-found error.
- Malformed YAML: `config.Load`'s existing error, wrapped with the file
  name for context.
- Unknown provider name (in the file, or passed to `--provider`): explicit
  error naming the bad value.
- `passphrase` provider errors (missing `GIT_VAULT_PASSPHRASE`, wrong
  passphrase on decrypt) are unchanged from `internal/keyservice/passphrase`
  and propagate as today (`RunE` → stderr → exit 1).

## Testing

- `internal/cli`: `TestNewLocalVault_ReturnsVaultAndRecipient`,
  `TestInstallCmd_SetsRepoLocalFilterConfig`,
  `TestInstallCmd_Global_SetsGlobalFilterConfig`, and the
  `encrypt`+`decrypt`/`clean`+`smudge` round-trip tests currently invoke
  commands without ever writing `.git-vault.yaml`. Each is updated to
  either run `install` first (for install/round-trip tests) or write
  `.git-vault.yaml` directly via `config.Save` in test setup (for the
  `newVault`-level test), so the new "config required" error doesn't break
  them.
- New: `newVault()`/`vaultForProvider` dispatch for `"passphrase"`; unknown
  provider name error; missing-config error (no `.git-vault.yaml` in a
  fresh temp dir); `install --provider=passphrase` writes
  `provider: passphrase` to `.git-vault.yaml` and fails (without touching
  git config) when `GIT_VAULT_PASSPHRASE` is unset; `install
  --provider=bogus` fails the same way.
