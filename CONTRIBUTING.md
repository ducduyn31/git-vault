# Contributing to git-vault

Thanks for helping out. This is a short guide — the details live where the
code does.

## Reporting a security issue

git-vault protects secrets, so please **do not** open a public issue for a
vulnerability. Use GitHub's private vulnerability reporting on this repo
instead.

## Getting set up

Build, test, lint, and format commands are in
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md). The short version:

```sh
task build   # build the git-vault binary
task test    # fast, hermetic tests
task lint    # golangci-lint
task fmt     # gofumpt
```

`task test:integration` runs the container-backed tests behind the
`integration` build tag; those need a running Docker daemon.

A Nix flake is provided if you'd rather not install the tools yourself:
`nix develop`.

## Before you open a pull request

- `task test` and `task lint` pass locally. CI runs `go build ./...`,
  `go test ./...`, and golangci-lint on every pull request.
- New behaviour comes with tests. Provider work in particular should cover
  the failure path — git-vault fails closed, and a provider that silently
  degrades is a bug.
- Update the docs that the change affects (`README.md`, the provider guides
  under `docs/`).

## Commit messages

Conventional Commits with a scope, matching the existing history:

```
feat(cli): support git vault migrate for --provider vault
test(hcvault): add testcontainers-backed real Vault integration test
docs(readme): rename team key-sharing heading now that it covers Vault too
```

Common types here: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`. The
scope is usually the package or command being touched. Keep the subject in
the imperative mood and under ~72 characters.

## Pull requests

Say what changed and why. Keep one logical change per pull request — a
refactor and a feature in the same branch are hard to review and harder to
revert.
