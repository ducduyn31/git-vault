# Developing git-vault

This project uses [go-task](https://taskfile.dev) for common commands:

```sh
task build   # build the git-vault binary
task test    # run the test suite
task lint    # run golangci-lint
task fmt     # format code with gofumpt
task install # install git-vault to $GOBIN
```

A Nix flake (`flake.nix`) provides a dev shell with the required tools:

```sh
nix develop
```

## Design docs

Design specs and plans live under `docs/superpowers/specs/` and
`docs/superpowers/plans/`.
