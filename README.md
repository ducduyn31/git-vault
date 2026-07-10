# git-vault

`git-vault` is a Go-based git extension that transparently encrypts secret
files in a repository, using a pluggable key-provider system built on
[sops](https://github.com/getsops/sops)'s keyservice protocol.

**Status:** pre-alpha, scaffold stage — no encryption or key provider is
implemented yet. See `docs/superpowers/specs/` for the design docs driving
this repo.

## Development

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
