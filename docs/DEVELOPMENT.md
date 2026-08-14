# Developing git-vault

This project uses [go-task](https://taskfile.dev) for common commands:

```sh
task build   # build the git-vault binary
task test    # run the test suite
task lint    # run golangci-lint
task fmt     # format code with gofumpt
task install # install git-vault to $GOBIN
```

`task test` runs only the fast, hermetic tests. Container-backed
integration tests sit behind the `integration` build tag and need a running
Docker daemon (they start real servers via
[testcontainers](https://golang.testcontainers.org/)):

```sh
task test:integration
```

Today that covers the HashiCorp Vault provider against a real Vault Transit
engine — the versioned `vault:v1:`/`vault:v2:` ciphertext format across a
real key rotation, and token resolution from `VAULT_TOKEN`, neither of which
the in-process fake server can model.

A Nix flake (`flake.nix`) provides a dev shell with the required tools:

```sh
nix develop
```

## Design docs

Design specs and plans live under `docs/superpowers/specs/` and
`docs/superpowers/plans/`.
