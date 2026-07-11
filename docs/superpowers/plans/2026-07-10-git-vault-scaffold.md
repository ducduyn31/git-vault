# git-vault: project scaffold Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the initial professional project scaffold for `git-vault` — repo layout, tooling, CI, and package boundaries — with no real encryption/provider logic, per `docs/superpowers/specs/2026-07-10-git-vault-scaffold-design.md` and `docs/superpowers/specs/2026-07-10-git-vault-ux-safety-design.md`.

**Architecture:** A cobra CLI (`cmd/git-vault`) wires nine subcommands defined in `internal/cli`. `internal/gitattr`, `internal/session`, and `internal/config` are simple, fully-working non-crypto utility packages (file/text manipulation) built with real logic and unit tests in this scaffold. `internal/keyservice` implements sops's real `KeyServiceServer` interface with a working `Provider` registry and dispatch (also real, tested, non-crypto plumbing), but ships only a `StubProvider` whose `Encrypt`/`Decrypt` return "not implemented" — real key backends are follow-up work. `internal/vault` is a thin, currently-stubbed wrapper around sops-as-a-library. Tooling (Nix flake, Taskfile, golangci-lint, goreleaser, GitHub Actions) rounds out a buildable, lintable, testable repo.

**Tech Stack:** Go (see Global Constraints for exact floor), `github.com/spf13/cobra` (CLI), `github.com/stretchr/testify` (test assertions), `github.com/getsops/sops/v3` (library + keyservice proto), `google.golang.org/grpc` (codes/status only), `gopkg.in/yaml.v3`, go-task, golangci-lint, goreleaser, Nix flakes, GitHub Actions. Every dependency is added at its latest published version (`go get <module>@latest`).

## Global Constraints

- **Go version: `1.26.5` (latest stable), not the spec's stated `1.23`.** `github.com/getsops/sops/v3`'s own `go.mod` declares `go 1.25.8` (verified directly: `curl -s https://raw.githubusercontent.com/getsops/sops/main/go.mod`) — Go's module graph requires every consumer to declare a `go` directive at least as high as its dependencies', so once sops v3 is added (Task 7), `1.23` is not achievable; `1.25.8` is the real floor. Rather than pin exactly to that floor, this plan uses `1.26.5`, the latest stable Go release as of writing (confirmed via `https://go.dev/dl/?mode=json`), which comfortably clears it. `go.mod`, both GitHub Actions workflows, and `.golangci.yml`'s `run.go` all use `1.26.5` (or `1.26` where only minor precision is idiomatic) for this reason. Module path stays `github.com/ducduyn31/git-vault`.
- License: not added yet (deferred past this scaffold pass) — no `LICENSE` file, no "License" section in `README.md`.
- Scaffold only: no real key provider, no real sops crypto integration, no published releases (per spec `Status: approved (scaffold only — no crypto/backend logic implemented yet)`).
- `.gitattributes` is the single source of truth for git-vault-tracked patterns — git-vault keeps no separate pattern-tracking config file.
- Session cache lives at `~/.cache/git-vault/session.json`; nothing about it is ever staged/committed.
- Repo-tracked `.git-vault.yaml` holds only non-secret settings (provider name, issuer URL, client id).
- git-vault's local `KeyServiceServer` dispatches by reinterpreting the sops `age_key.recipient` string field as an opaque `"<provider>:<key-id>"` identifier — **not** a real age recipient. This is the approved resolution to sops's keyservice `key_type` oneof being a closed set (kms/pgp/gcp_kms/azure_keyvault/vault/age/hckms) with no extension point for a custom key type without forking sops. It preserves "one local `KeyServiceServer` dispatching to a pluggable `Provider`" and "sops unmodified" from the spec, at the cost of the `age` field carrying a non-age meaning (documented inline everywhere it's used).
- No pre-commit hook is installed by git-vault (fail-closed filter is the safety net; `git vault status` is available for a user's own hook/CI to call).
- `gitattr`, `session`, and `config` get real implementations with unit tests in this scaffold (they are plain file/text logic, not crypto). `keyservice`'s `Provider` backend and `vault`'s `Seal`/`Open` stay stubs returning a not-implemented error — real logic is explicitly follow-up work per the spec's non-goals.
- **Why `track` is real but `install` stays a stub (this is not an inconsistency to "fix"):** `install` would set `filter.git-vault.required = true`, which makes git abort any add/checkout of a git-vault-tracked file if the filter driver errors. Since `clean`/`smudge` are stubs that always error, activating `install` for real today would put every tracked file into a permanently broken state. `track` only appends a `.gitattributes` line and activates nothing (same as `git lfs track` being safe to run standalone) — so it's safe to implement now. `install` becomes real together with `clean`/`smudge` in follow-up work, not before.
- All test files use `github.com/stretchr/testify/require` for assertions instead of hand-rolled `if ... { t.Fatalf(...) }` checks.
- CLI stub subcommands (`login`, `install`, `encrypt`, `decrypt`, `clean`, `smudge`, `status`) return an error whose message contains the exact substring `not implemented in scaffold`.
- Every Go-code-touching task ends with `gofumpt -l -w .` before committing — `.golangci.yml` (Task 9) enables gofumpt as a formatter, and CI will fail lint on unformatted code otherwise.

---

### Task 1: Repo bootstrap

**Files:**
- Create: `go.mod`
- Create: `.gitignore`
- Create: `.editorconfig`
- Create: `README.md`

**Interfaces:**
- Produces: a Go module `github.com/ducduyn31/git-vault` that later tasks add packages into.

- [ ] **Step 1: Initialize the Go module**

Run: `cd /Users/danielng/PersonalProjects/git-vault && go mod init github.com/ducduyn31/git-vault`

Expected output: `go: creating new go.mod: module github.com/ducduyn31/git-vault`

Then edit `go.mod` so the `go` directive reads `go 1.26.5` (see Global Constraints for why — sops v3, added in Task 7, requires it):

```
module github.com/ducduyn31/git-vault

go 1.26.5
```

- [ ] **Step 2: Add .gitignore**

Create `.gitignore`:

```
# Build output
/git-vault
/dist/

# Go
*.test
*.out

# Nix
result
result-*

# Editor/OS
.DS_Store
```

- [ ] **Step 3: Add .editorconfig**

Create `.editorconfig`:

```
root = true

[*]
charset = utf-8
end_of_line = lf
insert_final_newline = true
trim_trailing_whitespace = true
indent_style = space
indent_size = 2

[*.go]
indent_style = tab

[Makefile]
indent_style = tab
```

- [ ] **Step 4: Add README skeleton**

Create `README.md`:

```markdown
# git-vault

`git-vault` is a Go-based git extension that transparently encrypts secret
files in a repository, using a pluggable key-provider system built on
[sops](https://github.com/getsops/sops)'s keyservice protocol.

**Status:** pre-alpha, scaffold stage — no encryption or key provider is
implemented yet. See `docs/superpowers/specs/` for the design docs driving
this repo.

## Development

This project uses [go-task](https://taskfile.dev) for common commands:

\`\`\`sh
task build   # build the git-vault binary
task test    # run the test suite
task lint    # run golangci-lint
task fmt     # format code with gofumpt
task install # install git-vault to $GOBIN
\`\`\`

A Nix flake (`flake.nix`) provides a dev shell with the required tools:

\`\`\`sh
nix develop
\`\`\`
```

- [ ] **Step 5: Verify the module builds**

Run: `go build ./...`
Expected: no output, exit code 0 (no packages yet, this just confirms `go.mod` is valid).

- [ ] **Step 6: Commit**

```bash
git add go.mod .gitignore .editorconfig README.md
git commit -m "chore: bootstrap go module and repo metadata"
```

---

### Task 2: CLI skeleton — root command, version, and stub subcommands

**Files:**
- Create: `cmd/git-vault/main.go`
- Create: `internal/cli/root.go`
- Create: `internal/cli/version.go`
- Create: `internal/cli/login.go`
- Create: `internal/cli/track.go`
- Create: `internal/cli/install.go`
- Create: `internal/cli/encrypt.go`
- Create: `internal/cli/decrypt.go`
- Create: `internal/cli/clean.go`
- Create: `internal/cli/smudge.go`
- Create: `internal/cli/status.go`
- Create: `internal/cli/root_test.go`

**Interfaces:**
- Produces: `cli.NewRootCmd() *cobra.Command`, `cli.Execute() error`, `cli.Version` (string var, default `"dev"`).
- Consumes: nothing from other tasks yet (`track` here is a stub; Task 3 rewrites it to call `internal/gitattr`).

- [ ] **Step 1: Add dependencies**

Run: `go get github.com/spf13/cobra@latest github.com/stretchr/testify@latest`

- [ ] **Step 2: Write the failing smoke test**

Create `internal/cli/root_test.go`:

```go
package cli

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExecute_Help(t *testing.T) {
	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--help"})

	require.NoError(t, cmd.Execute())
}

func TestVersionCmd_PrintsVersion(t *testing.T) {
	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{"version"})

	require.NoError(t, cmd.Execute())
	require.Equal(t, "dev\n", out.String())
}

func TestStubCommands_NotImplemented(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"login", []string{"login"}},
		{"track", []string{"track", "*.secret.yaml"}},
		{"install", []string{"install"}},
		{"encrypt", []string{"encrypt", "file.txt"}},
		{"decrypt", []string{"decrypt", "file.txt"}},
		{"clean", []string{"clean", "file.txt"}},
		{"smudge", []string{"smudge", "file.txt"}},
		{"status", []string{"status"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := NewRootCmd()
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})
			cmd.SetArgs(tc.args)

			err := cmd.Execute()
			require.ErrorContains(t, err, "not implemented in scaffold")
		})
	}
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./internal/cli/...`
Expected: FAIL — `NewRootCmd` undefined (package doesn't exist yet).

- [ ] **Step 4: Write the root command**

Create `internal/cli/root.go`:

```go
package cli

import "github.com/spf13/cobra"

// NewRootCmd builds the git-vault root cobra command with all subcommands
// wired in.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "git-vault",
		Short: "Transparently encrypt secret files in a git repository",
	}
	root.AddCommand(
		newLoginCmd(),
		newTrackCmd(),
		newInstallCmd(),
		newEncryptCmd(),
		newDecryptCmd(),
		newCleanCmd(),
		newSmudgeCmd(),
		newStatusCmd(),
		newVersionCmd(),
	)
	return root
}

// Execute runs the root command against the real process args.
func Execute() error {
	return NewRootCmd().Execute()
}
```

- [ ] **Step 5: Write the version command**

Create `internal/cli/version.go`:

```go
package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version is the git-vault release version. It is overridden via
// -ldflags "-X github.com/ducduyn31/git-vault/internal/cli.Version=..."
// at release build time (see .goreleaser.yaml).
var Version = "dev"

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the git-vault version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), Version)
			return nil
		},
	}
}
```

- [ ] **Step 6: Write the stub subcommands**

Create `internal/cli/login.go`:

```go
package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newLoginCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Authenticate with a git-vault key provider",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("git vault login: not implemented in scaffold")
		},
	}
}
```

Create `internal/cli/track.go` (temporary stub; Task 3 replaces the body):

```go
package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newTrackCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "track <pattern>",
		Short: "Track a file pattern for git-vault encryption",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("git vault track: not implemented in scaffold")
		},
	}
}
```

Create `internal/cli/install.go`:

```go
package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newInstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Register the git-vault filter driver",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("git vault install: not implemented in scaffold")
		},
	}
	cmd.Flags().Bool("global", false, "install the filter driver in the user's global git config")
	return cmd
}
```

Create `internal/cli/encrypt.go`:

```go
package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newEncryptCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "encrypt <file>",
		Short: "Encrypt a file in place, outside the filter path",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("git vault encrypt: not implemented in scaffold")
		},
	}
}
```

Create `internal/cli/decrypt.go`:

```go
package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newDecryptCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "decrypt <file>",
		Short: "Decrypt a file in place, outside the filter path",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("git vault decrypt: not implemented in scaffold")
		},
	}
}
```

Create `internal/cli/clean.go`:

```go
package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newCleanCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "clean [path]",
		Short:  "Git clean filter entry point (encrypt on stage)",
		Args:   cobra.MaximumNArgs(1),
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("git vault clean: not implemented in scaffold")
		},
	}
}
```

Create `internal/cli/smudge.go`:

```go
package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newSmudgeCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "smudge [path]",
		Short:  "Git smudge filter entry point (decrypt on checkout)",
		Args:   cobra.MaximumNArgs(1),
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("git vault smudge: not implemented in scaffold")
		},
	}
}
```

Create `internal/cli/status.go`:

```go
package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show git-vault-tracked files and their encryption state",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("git vault status: not implemented in scaffold")
		},
	}
}
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `go test ./internal/cli/...`
Expected: `ok  	github.com/ducduyn31/git-vault/internal/cli`

- [ ] **Step 8: Wire up cmd/git-vault/main.go**

Create `cmd/git-vault/main.go`:

```go
package main

import (
	"fmt"
	"os"

	"github.com/ducduyn31/git-vault/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
```

Run: `go build ./...`
Expected: no output, exit code 0.

- [ ] **Step 9: Format and commit**

Run: `gofumpt -l -w .`

```bash
git add go.mod go.sum cmd internal/cli
git commit -m "feat: scaffold cobra CLI with version command and stub subcommands"
```

---

### Task 3: internal/gitattr — real `.gitattributes` tracking, wired to `track`

**Files:**
- Create: `internal/gitattr/gitattr.go`
- Create: `internal/gitattr/gitattr_test.go`
- Modify: `internal/cli/track.go`
- Modify: `internal/cli/root_test.go:` remove `"track"` from `TestStubCommands_NotImplemented`'s cases
- Create: `internal/cli/track_test.go`

**Interfaces:**
- Produces: `gitattr.Track(path, pattern string) error`, `gitattr.Tracked(path string) ([]string, error)`.
- Consumes (in `internal/cli/track.go`): the two functions above.

- [ ] **Step 1: Write the failing gitattr tests**

Create `internal/gitattr/gitattr_test.go`:

```go
package gitattr

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTrack_CreatesFileAndAppendsLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".gitattributes")

	require.NoError(t, Track(path, "secrets/*.yaml"))

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "secrets/*.yaml filter=git-vault diff=git-vault -text\n", string(got))
}

func TestTrack_IdempotentWhenAlreadyTracked(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".gitattributes")

	require.NoError(t, Track(path, "secrets/*.yaml"))
	require.NoError(t, Track(path, "secrets/*.yaml"))

	patterns, err := Tracked(path)
	require.NoError(t, err)
	require.Len(t, patterns, 1)
}

func TestTracked_ParsesOnlyGitVaultFilterLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".gitattributes")
	content := "*.bin binary\n" +
		"secrets/*.yaml filter=git-vault diff=git-vault -text\n" +
		"*.lfs filter=lfs diff=lfs merge=lfs -text\n" +
		"config/*.env filter=git-vault diff=git-vault -text\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	patterns, err := Tracked(path)
	require.NoError(t, err)
	require.Equal(t, []string{"secrets/*.yaml", "config/*.env"}, patterns)
}

func TestTracked_MissingFileReturnsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".gitattributes")

	patterns, err := Tracked(path)
	require.NoError(t, err)
	require.Empty(t, patterns)
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/gitattr/...`
Expected: FAIL — package `gitattr` doesn't exist yet.

- [ ] **Step 3: Implement internal/gitattr**

Create `internal/gitattr/gitattr.go`:

```go
// Package gitattr reads and writes the git-vault filter=git-vault lines in
// a .gitattributes file. .gitattributes is the single source of truth for
// which patterns git-vault tracks — this package never maintains its own
// separate config file.
package gitattr

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func attrLine(pattern string) string {
	return fmt.Sprintf("%s filter=git-vault diff=git-vault -text", pattern)
}

// Track appends a git-vault attribute line for pattern to the
// .gitattributes file at path, creating the file if it doesn't exist. It
// is a no-op if pattern is already tracked.
func Track(path, pattern string) error {
	lines, err := readLines(path)
	if err != nil {
		return err
	}

	want := attrLine(pattern)
	for _, line := range lines {
		if line == want {
			return nil
		}
	}

	lines = append(lines, want)
	return writeLines(path, lines)
}

// Tracked returns the patterns tracked by git-vault's filter in the
// .gitattributes file at path. It returns an empty slice if path doesn't
// exist.
func Tracked(path string) ([]string, error) {
	lines, err := readLines(path)
	if err != nil {
		return nil, err
	}

	var patterns []string
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		for _, f := range fields[1:] {
			if f == "filter=git-vault" {
				patterns = append(patterns, fields[0])
				break
			}
		}
	}
	return patterns, nil
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func writeLines(path string, lines []string) error {
	var b strings.Builder
	for _, line := range lines {
		b.WriteString(line)
		b.WriteString("\n")
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/gitattr/...`
Expected: `ok  	github.com/ducduyn31/git-vault/internal/gitattr`

- [ ] **Step 5: Write the failing track-command test**

Create `internal/cli/track_test.go`:

```go
package cli

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ducduyn31/git-vault/internal/gitattr"
)

func TestTrackCmd_AppendsPattern(t *testing.T) {
	dir := t.TempDir()
	old, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(old)

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"track", "secrets/*.yaml"})
	require.NoError(t, cmd.Execute())

	patterns, err := gitattr.Tracked(".gitattributes")
	require.NoError(t, err)
	require.Equal(t, []string{"secrets/*.yaml"}, patterns)
}
```

- [ ] **Step 6: Remove `track` from the stub-command test and rewrite the command**

Edit `internal/cli/root_test.go`: remove the `{"track", []string{"track", "*.secret.yaml"}},` line from the `cases` slice in `TestStubCommands_NotImplemented`.

Replace `internal/cli/track.go`:

```go
package cli

import (
	"github.com/spf13/cobra"

	"github.com/ducduyn31/git-vault/internal/gitattr"
)

func newTrackCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "track <pattern>",
		Short: "Track a file pattern for git-vault encryption",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return gitattr.Track(".gitattributes", args[0])
		},
	}
}
```

- [ ] **Step 7: Run the full internal/cli test suite to verify it passes**

Run: `go test ./internal/cli/... ./internal/gitattr/...`
Expected: both packages `ok`.

- [ ] **Step 8: Format and commit**

Run: `gofumpt -l -w .`

```bash
git add internal/gitattr internal/cli/track.go internal/cli/track_test.go internal/cli/root_test.go
git commit -m "feat: implement gitattr package and wire git vault track to it"
```

---

### Task 4: internal/session — local session cache

**Files:**
- Create: `internal/session/session.go`
- Create: `internal/session/session_test.go`

**Interfaces:**
- Produces: `session.Session{Provider, Token string; ExpiresAt time.Time}`, `(Session) Expired(now time.Time) bool`, `session.Save(path string, s Session) error`, `session.Load(path string) (Session, error)`, `session.DefaultPath() (string, error)`.
- Consumes: nothing from other tasks. Used by provider implementations in follow-up work, not wired into `login` in this scaffold (per Global Constraints: `login` stays a stub).

- [ ] **Step 1: Write the failing tests**

Create `internal/session/session_test.go`:

```go
package session

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSaveLoad_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	want := Session{
		Provider:  "sso",
		Token:     "abc123",
		ExpiresAt: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
	}

	require.NoError(t, Save(path, want))

	got, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestExpired(t *testing.T) {
	s := Session{ExpiresAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}

	require.True(t, s.Expired(time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)))
	require.False(t, s.Expired(time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC)))
}

func TestLoad_MissingFileReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.json")

	_, err := Load(path)
	require.Error(t, err)
}

func TestDefaultPath_EndsUnderGitVaultCacheDir(t *testing.T) {
	path, err := DefaultPath()
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(path, filepath.Join("git-vault", "session.json")))
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/session/...`
Expected: FAIL — package `session` doesn't exist yet.

- [ ] **Step 3: Implement internal/session**

Create `internal/session/session.go`:

```go
// Package session reads and writes git-vault's local session cache
// (~/.cache/git-vault/session.json). Not every Provider needs a session
// (e.g. a KMS-backed provider might use ambient cloud credentials
// instead) — this package is used by whichever providers need it, it is
// not a requirement of the Provider interface itself.
package session

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Session is a cached, short-lived credential for a key Provider.
type Session struct {
	Provider  string    `json:"provider"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Expired reports whether the session has expired as of now.
func (s Session) Expired(now time.Time) bool {
	return !s.ExpiresAt.After(now)
}

// DefaultPath returns the default session cache file path,
// ~/.cache/git-vault/session.json (honoring $XDG_CACHE_HOME on Linux via
// os.UserCacheDir).
func DefaultPath() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "git-vault", "session.json"), nil
}

// Load reads and parses the session file at path.
func Load(path string) (Session, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Session{}, err
	}
	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return Session{}, err
	}
	return s, nil
}

// Save writes s to path, creating parent directories as needed. The file
// is written with 0600 permissions since it holds credential material.
func Save(path string, s Session) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/session/...`
Expected: `ok  	github.com/ducduyn31/git-vault/internal/session`

- [ ] **Step 5: Format and commit**

Run: `gofumpt -l -w .`

```bash
git add internal/session
git commit -m "feat: implement local session cache package"
```

---

### Task 5: internal/config — repo-tracked settings

**Files:**
- Create: `internal/config/config.go`
- Create: `internal/config/config_test.go`

**Interfaces:**
- Produces: `config.Config{Provider, IssuerURL, ClientID string}`, `config.DefaultFileName` (const `".git-vault.yaml"`), `config.Load(path string) (Config, error)`, `config.Save(path string, c Config) error`.
- Consumes: nothing from other tasks. Not wired into any CLI command in this scaffold (no command reads/writes config yet — that lands with `login`/`install` in follow-up work).

- [ ] **Step 1: Add the yaml dependency**

Run: `go get gopkg.in/yaml.v3@latest`

- [ ] **Step 2: Write the failing tests**

Create `internal/config/config_test.go`:

```go
package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSaveLoad_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".git-vault.yaml")
	want := Config{
		Provider:  "sso",
		IssuerURL: "https://issuer.example.com",
		ClientID:  "git-vault-cli",
	}

	require.NoError(t, Save(path, want))

	got, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestLoad_MissingFileReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.yaml")

	_, err := Load(path)
	require.Error(t, err)
}

func TestLoad_MalformedYAMLReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".git-vault.yaml")
	require.NoError(t, os.WriteFile(path, []byte("provider: [this is not valid: yaml"), 0o644))

	_, err := Load(path)
	require.Error(t, err)
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./internal/config/...`
Expected: FAIL — package `config` doesn't exist yet.

- [ ] **Step 4: Implement internal/config**

Create `internal/config/config.go`:

```go
// Package config reads and writes git-vault's repo-tracked settings file
// (.git-vault.yaml). It holds only non-secret settings — actual key or
// session material always lives in internal/session's cache, never here.
package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// DefaultFileName is the repo-relative path git-vault's settings file is
// conventionally stored at.
const DefaultFileName = ".git-vault.yaml"

// Config holds git-vault's non-secret, repo-tracked settings.
type Config struct {
	Provider  string `yaml:"provider"`
	IssuerURL string `yaml:"issuer_url,omitempty"`
	ClientID  string `yaml:"client_id,omitempty"`
}

// Load reads and parses the config file at path.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Save writes c to path.
func Save(path string, c Config) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/config/...`
Expected: `ok  	github.com/ducduyn31/git-vault/internal/config`

- [ ] **Step 6: Format and commit**

Run: `gofumpt -l -w .`

```bash
git add go.mod go.sum internal/config
git commit -m "feat: implement repo-tracked config package"
```

---

### Task 6: internal/keyservice — Provider interface and registry

**Files:**
- Create: `internal/keyservice/provider.go`
- Create: `internal/keyservice/registry.go`
- Create: `internal/keyservice/registry_test.go`

**Interfaces:**
- Produces: `keyservice.Provider` interface (`Name() string`, `Encrypt(ctx, keyID string, plaintext []byte) ([]byte, error)`, `Decrypt(ctx, keyID string, ciphertext []byte) ([]byte, error)`), `keyservice.NewRegistry() *Registry`, `(*Registry) Register(p Provider) error`, `(*Registry) Get(name string) (Provider, bool)`.
- Consumes: nothing from other tasks. Task 7 consumes `Provider` and `*Registry` from this task.

- [ ] **Step 1: Write the failing registry tests**

Create `internal/keyservice/registry_test.go`:

```go
package keyservice

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

type fakeProvider struct {
	name string
}

func (p fakeProvider) Name() string { return p.name }

func (p fakeProvider) Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error) {
	return plaintext, nil
}

func (p fakeProvider) Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error) {
	return ciphertext, nil
}

func TestRegistry_RegisterAndGet(t *testing.T) {
	r := NewRegistry()
	p := fakeProvider{name: "sso"}

	require.NoError(t, r.Register(p))

	got, ok := r.Get("sso")
	require.True(t, ok)
	require.Equal(t, "sso", got.Name())
}

func TestRegistry_DuplicateRegisterErrors(t *testing.T) {
	r := NewRegistry()
	p := fakeProvider{name: "sso"}

	require.NoError(t, r.Register(p))
	require.Error(t, r.Register(p))
}

func TestRegistry_GetUnknownReturnsFalse(t *testing.T) {
	r := NewRegistry()

	_, ok := r.Get("does-not-exist")
	require.False(t, ok)
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/keyservice/...`
Expected: FAIL — package `keyservice` doesn't exist yet.

- [ ] **Step 3: Implement Provider and Registry**

Create `internal/keyservice/provider.go`:

```go
// Package keyservice implements sops's KeyServiceServer extension point
// (see github.com/getsops/sops/v3/keyservice), dispatching Encrypt/Decrypt
// calls to a pluggable Provider rather than a fixed set of key backends
// compiled into sops itself. SSO is the first Provider; adding a new
// backend later means implementing this interface and registering it — no
// changes to internal/vault, internal/cli, or sops.
package keyservice

import "context"

// Provider performs Encrypt/Decrypt of a sops data key on behalf of one
// key backend (SSO, an internal KMS, Vault, ...). keyID is opaque to
// git-vault's Server — each Provider defines its own format for it.
type Provider interface {
	// Name identifies this provider in a "<provider>:<key-id>" identifier
	// (see Server in server.go).
	Name() string
	Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error)
}
```

Create `internal/keyservice/registry.go`:

```go
package keyservice

import (
	"fmt"
	"sync"
)

// Registry looks up a Provider by name. It is safe for concurrent use.
type Registry struct {
	mu        sync.RWMutex
	providers map[string]Provider
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{providers: make(map[string]Provider)}
}

// Register adds p to the registry under p.Name(). It errors if a provider
// with that name is already registered.
func (r *Registry) Register(p Provider) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.providers[p.Name()]; exists {
		return fmt.Errorf("keyservice: provider %q already registered", p.Name())
	}
	r.providers[p.Name()] = p
	return nil
}

// Get returns the provider registered under name, if any.
func (r *Registry) Get(name string) (Provider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	p, ok := r.providers[name]
	return p, ok
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/keyservice/...`
Expected: `ok  	github.com/ducduyn31/git-vault/internal/keyservice`

- [ ] **Step 5: Format and commit**

Run: `gofumpt -l -w .`

```bash
git add internal/keyservice/provider.go internal/keyservice/registry.go internal/keyservice/registry_test.go
git commit -m "feat: add keyservice Provider interface and registry"
```

---

### Task 7: internal/keyservice — sops KeyServiceServer dispatch and StubProvider

**Files:**
- Create: `internal/keyservice/server.go`
- Create: `internal/keyservice/server_test.go`
- Create: `internal/keyservice/stub_provider.go`
- Create: `internal/keyservice/stub_provider_test.go`

**Interfaces:**
- Consumes: `keyservice.Provider`, `keyservice.Registry` (Task 6).
- Produces: `keyservice.Server` (implements `sopskeyservice.KeyServiceServer`: `Encrypt`, `Decrypt`), `keyservice.NewServer(r *Registry) *Server`, `keyservice.StubProvider{ProviderName string}` (implements `Provider`).

- [ ] **Step 1: Add the sops and grpc dependencies**

Run: `go get github.com/getsops/sops/v3@latest google.golang.org/grpc@latest`

sops v3 requires `go 1.25.8` at minimum — our `go.mod` is already at `1.26.5` (Task 1), so this should not force a bump. Confirm with `go list -m -f '{{.GoVersion}}' github.com/getsops/sops/v3` if `go get` reports a mismatch.

- [ ] **Step 2: Write the failing server tests**

Create `internal/keyservice/server_test.go`:

```go
package keyservice

import (
	"context"
	"errors"
	"testing"

	sopskeyservice "github.com/getsops/sops/v3/keyservice"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type recordingProvider struct {
	name       string
	decryptErr error
}

func (p recordingProvider) Name() string { return p.name }

func (p recordingProvider) Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error) {
	return append([]byte("enc:"+keyID+":"), plaintext...), nil
}

func (p recordingProvider) Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error) {
	if p.decryptErr != nil {
		return nil, p.decryptErr
	}
	return []byte("plaintext"), nil
}

func ageKey(recipient string) *sopskeyservice.Key {
	return &sopskeyservice.Key{
		KeyType: &sopskeyservice.Key_AgeKey{
			AgeKey: &sopskeyservice.AgeKey{Recipient: recipient},
		},
	}
}

func TestServer_Encrypt_DispatchesToProvider(t *testing.T) {
	registry := NewRegistry()
	require.NoError(t, registry.Register(recordingProvider{name: "sso"}))
	server := NewServer(registry)

	resp, err := server.Encrypt(context.Background(), &sopskeyservice.EncryptRequest{
		Key:       ageKey("sso:my-key"),
		Plaintext: []byte("secret"),
	})
	require.NoError(t, err)
	require.Equal(t, "enc:my-key:secret", string(resp.GetCiphertext()))
}

func TestServer_Decrypt_DispatchesToProvider(t *testing.T) {
	registry := NewRegistry()
	require.NoError(t, registry.Register(recordingProvider{name: "sso"}))
	server := NewServer(registry)

	resp, err := server.Decrypt(context.Background(), &sopskeyservice.DecryptRequest{
		Key:        ageKey("sso:my-key"),
		Ciphertext: []byte("enc:my-key:secret"),
	})
	require.NoError(t, err)
	require.Equal(t, "plaintext", string(resp.GetPlaintext()))
}

func TestServer_UnknownProvider_ReturnsNotFound(t *testing.T) {
	server := NewServer(NewRegistry())

	_, err := server.Encrypt(context.Background(), &sopskeyservice.EncryptRequest{
		Key:       ageKey("does-not-exist:my-key"),
		Plaintext: []byte("secret"),
	})
	require.Equal(t, codes.NotFound, status.Code(err))
}

func TestServer_MalformedIdentifier_ReturnsInvalidArgument(t *testing.T) {
	server := NewServer(NewRegistry())

	_, err := server.Encrypt(context.Background(), &sopskeyservice.EncryptRequest{
		Key:       ageKey("no-colon-here"),
		Plaintext: []byte("secret"),
	})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestServer_NonAgeKeyType_ReturnsInvalidArgument(t *testing.T) {
	server := NewServer(NewRegistry())

	_, err := server.Encrypt(context.Background(), &sopskeyservice.EncryptRequest{
		Key: &sopskeyservice.Key{
			KeyType: &sopskeyservice.Key_PgpKey{PgpKey: &sopskeyservice.PgpKey{}},
		},
		Plaintext: []byte("secret"),
	})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestServer_ProviderError_ReturnsInternal(t *testing.T) {
	registry := NewRegistry()
	require.NoError(t, registry.Register(recordingProvider{name: "sso", decryptErr: errors.New("boom")}))
	server := NewServer(registry)

	_, err := server.Decrypt(context.Background(), &sopskeyservice.DecryptRequest{
		Key:        ageKey("sso:my-key"),
		Ciphertext: []byte("whatever"),
	})
	require.Equal(t, codes.Internal, status.Code(err))
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./internal/keyservice/...`
Expected: FAIL — `NewServer` undefined.

- [ ] **Step 4: Implement Server**

Create `internal/keyservice/server.go`:

```go
package keyservice

import (
	"context"
	"strings"

	sopskeyservice "github.com/getsops/sops/v3/keyservice"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server implements sops's KeyServiceServer by dispatching to git-vault's
// own pluggable Provider registry.
//
// sops's keyservice protocol has a fixed, closed set of key types (kms,
// pgp, gcp_kms, azure_keyvault, vault, age, hckms) with no extension point
// for a new one without forking sops. git-vault reuses the age key type's
// `recipient` string as an opaque carrier: it is never a real age
// recipient, only a "<provider-name>:<key-id>" identifier that Server
// parses and routes to the matching Provider. Any other key type is
// rejected — git-vault only ever writes age-shaped entries for its own
// provider keys.
type Server struct {
	sopskeyservice.UnimplementedKeyServiceServer
	registry *Registry
}

// NewServer returns a Server that dispatches to registry.
func NewServer(registry *Registry) *Server {
	return &Server{registry: registry}
}

var _ sopskeyservice.KeyServiceServer = (*Server)(nil)

func (s *Server) Encrypt(ctx context.Context, req *sopskeyservice.EncryptRequest) (*sopskeyservice.EncryptResponse, error) {
	provider, keyID, err := s.resolve(req.GetKey())
	if err != nil {
		return nil, err
	}
	ciphertext, err := provider.Encrypt(ctx, keyID, req.GetPlaintext())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "provider %q encrypt: %v", provider.Name(), err)
	}
	return &sopskeyservice.EncryptResponse{Ciphertext: ciphertext}, nil
}

func (s *Server) Decrypt(ctx context.Context, req *sopskeyservice.DecryptRequest) (*sopskeyservice.DecryptResponse, error) {
	provider, keyID, err := s.resolve(req.GetKey())
	if err != nil {
		return nil, err
	}
	plaintext, err := provider.Decrypt(ctx, keyID, req.GetCiphertext())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "provider %q decrypt: %v", provider.Name(), err)
	}
	return &sopskeyservice.DecryptResponse{Plaintext: plaintext}, nil
}

// resolve extracts "<provider>:<key-id>" from the age key's recipient
// field and looks up the matching Provider.
func (s *Server) resolve(key *sopskeyservice.Key) (Provider, string, error) {
	ageKey := key.GetAgeKey()
	if ageKey == nil {
		return nil, "", status.Errorf(codes.InvalidArgument, "git-vault only handles age-shaped key entries, got %T", key.GetKeyType())
	}

	name, keyID, ok := strings.Cut(ageKey.GetRecipient(), ":")
	if !ok {
		return nil, "", status.Errorf(codes.InvalidArgument, "malformed git-vault key identifier %q, want \"<provider>:<key-id>\"", ageKey.GetRecipient())
	}

	provider, found := s.registry.Get(name)
	if !found {
		return nil, "", status.Errorf(codes.NotFound, "no provider registered for %q", name)
	}
	return provider, keyID, nil
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/keyservice/...`
Expected: `ok  	github.com/ducduyn31/git-vault/internal/keyservice`

- [ ] **Step 6: Write the failing StubProvider test**

Create `internal/keyservice/stub_provider_test.go`:

```go
package keyservice

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStubProvider_EncryptReturnsNotImplemented(t *testing.T) {
	p := StubProvider{ProviderName: "sso"}

	_, err := p.Encrypt(context.Background(), "my-key", []byte("secret"))
	require.Error(t, err)
}

func TestStubProvider_DecryptReturnsNotImplemented(t *testing.T) {
	p := StubProvider{ProviderName: "sso"}

	_, err := p.Decrypt(context.Background(), "my-key", []byte("ciphertext"))
	require.Error(t, err)
}

func TestStubProvider_Name(t *testing.T) {
	p := StubProvider{ProviderName: "sso"}

	require.Equal(t, "sso", p.Name())
}
```

- [ ] **Step 7: Run the test to verify it fails**

Run: `go test ./internal/keyservice/...`
Expected: FAIL — `StubProvider` undefined.

- [ ] **Step 8: Implement StubProvider**

Create `internal/keyservice/stub_provider.go`:

```go
package keyservice

import (
	"context"
	"fmt"
)

// StubProvider is a Provider that always errors. It exists so the CLI and
// Server have something registrable to exercise the scaffold's wiring
// without any real key backend implemented yet (see the scaffold design
// doc's non-goals). A real provider (e.g. SSO-backed) replaces this in
// follow-up work.
type StubProvider struct {
	ProviderName string
}

func (p StubProvider) Name() string { return p.ProviderName }

func (p StubProvider) Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error) {
	return nil, fmt.Errorf("keyservice: provider %q: not implemented in scaffold", p.ProviderName)
}

func (p StubProvider) Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error) {
	return nil, fmt.Errorf("keyservice: provider %q: not implemented in scaffold", p.ProviderName)
}
```

- [ ] **Step 9: Run the full keyservice suite to verify it passes**

Run: `go test ./internal/keyservice/...`
Expected: `ok  	github.com/ducduyn31/git-vault/internal/keyservice`

- [ ] **Step 10: Format and commit**

Run: `gofumpt -l -w .`

```bash
git add go.mod go.sum internal/keyservice
git commit -m "feat: implement sops KeyServiceServer dispatch and StubProvider"
```

---

### Task 8: internal/vault — stubbed sops wrapper

**Files:**
- Create: `internal/vault/vault.go`
- Create: `internal/vault/vault_test.go`

**Interfaces:**
- Produces: `vault.ErrNotImplemented` (error), `vault.Vault{KeyserviceAddr string}`, `vault.New(keyserviceAddr string) *Vault`, `(*Vault) Seal(path string) error`, `(*Vault) Open(path string) error`.
- Consumes: nothing from other tasks in this scaffold. Real logic (calling sops-as-a-library configured to use `internal/keyservice.Server` over the local keyservice endpoint) is follow-up work per the spec's non-goals.

- [ ] **Step 1: Write the failing tests**

Create `internal/vault/vault_test.go`:

```go
package vault

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSeal_ReturnsNotImplemented(t *testing.T) {
	v := New("unix:///tmp/git-vault-keyservice.sock")

	require.ErrorIs(t, v.Seal("secret.yaml"), ErrNotImplemented)
}

func TestOpen_ReturnsNotImplemented(t *testing.T) {
	v := New("unix:///tmp/git-vault-keyservice.sock")

	require.ErrorIs(t, v.Open("secret.yaml"), ErrNotImplemented)
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/vault/...`
Expected: FAIL — package `vault` doesn't exist yet.

- [ ] **Step 3: Implement internal/vault**

Create `internal/vault/vault.go`:

```go
// Package vault will wrap sops-as-a-library, configured to route key
// operations through git-vault's local keyservice (internal/keyservice).
// Per the scaffold design doc's non-goals, no real sops integration logic
// is implemented yet — Seal and Open are stubs. Follow-up work replaces
// them with real sops Encrypt/Decrypt tree calls (streaming, for
// clean/smudge).
package vault

import "errors"

// ErrNotImplemented is returned by every Vault operation until real sops
// integration lands.
var ErrNotImplemented = errors.New("vault: not implemented")

// Vault seals/opens files using sops, dialing KeyserviceAddr for key
// operations.
type Vault struct {
	KeyserviceAddr string
}

// New returns a Vault configured to use the keyservice at keyserviceAddr.
func New(keyserviceAddr string) *Vault {
	return &Vault{KeyserviceAddr: keyserviceAddr}
}

// Seal encrypts the file at path in place.
func (v *Vault) Seal(path string) error {
	return ErrNotImplemented
}

// Open decrypts the file at path in place.
func (v *Vault) Open(path string) error {
	return ErrNotImplemented
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/vault/...`
Expected: `ok  	github.com/ducduyn31/git-vault/internal/vault`

- [ ] **Step 5: Run the entire test suite**

Run: `go test ./...`
Expected: every package `ok`.

- [ ] **Step 6: Format and commit**

Run: `gofumpt -l -w .`

```bash
git add internal/vault
git commit -m "feat: add stubbed vault package"
```

---

### Task 9: Tooling — golangci-lint and go-task

**Files:**
- Create: `.golangci.yml`
- Create: `Taskfile.yml`

**Interfaces:**
- Produces: `task build|test|lint|fmt|install` entry points used by Task 11's CI workflow.

- [ ] **Step 1: Add .golangci.yml**

Create `.golangci.yml`:

```yaml
version: "2"

run:
  timeout: 5m
  go: "1.26"

linters:
  default: standard # = errcheck, govet, ineffassign, staticcheck, unused

formatters:
  enable:
    - gofumpt
```

- [ ] **Step 2: Add Taskfile.yml**

Create `Taskfile.yml`:

```yaml
version: '3'

vars:
  BIN: git-vault
  PKG: ./cmd/git-vault

tasks:
  default:
    desc: List available tasks
    cmds:
      - task --list
    silent: true

  build:
    desc: Build the git-vault binary
    sources:
      - '**/*.go'
      - go.mod
      - go.sum
    generates:
      - '{{.BIN}}'
    cmds:
      - go build -o {{.BIN}} {{.PKG}}

  test:
    desc: Run the test suite
    cmds:
      - go test ./...

  lint:
    desc: Run golangci-lint
    cmds:
      - golangci-lint run

  fmt:
    desc: Format code with gofumpt
    cmds:
      - gofumpt -l -w .

  install:
    desc: Install the git-vault binary to GOBIN
    cmds:
      - go install {{.PKG}}
```

- [ ] **Step 3: Verify go-task can parse the Taskfile and run build/test**

Run: `task build && task test`
Expected: binary builds, all tests pass. (If `task` isn't installed locally yet, run `go build ./cmd/git-vault && go test ./...` instead to verify the underlying commands work — `task` itself is exercised for real once the Task 10 dev shell is available.)

- [ ] **Step 4: Commit**

```bash
git add .golangci.yml Taskfile.yml
git commit -m "chore: add golangci-lint config and Taskfile"
```

---

### Task 10: Nix flake

**Files:**
- Create: `flake.nix`

**Interfaces:**
- Produces: `nix build` (package output), `nix develop` (dev shell with go, golangci-lint, goreleaser, gofumpt, go-task).

- [ ] **Step 1: Add flake.nix**

Create `flake.nix`:

```nix
{
  description = "git-vault CLI";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        # Uses nixpkgs' default Go toolchain rather than pinning an exact
        # version. go.mod requires >= 1.26.5 (latest stable at time of
        # writing) — if this nixpkgs revision's default `go` is an older
        # patch of 1.26.x, `nix build`/`nix develop` will fail needing a
        # newer toolchain; bump the `nixpkgs` input above to a revision
        # that ships >= 1.26.5 rather than pinning an exact Go derivation
        # here (keeps golangci-lint/goreleaser on current versions too).
        packages.default = pkgs.buildGoModule {
          pname = "git-vault";
          version = "0.1.0";
          src = ./.;
          subPackages = [ "cmd/git-vault" ];

          # Placeholder — Step 2 below replaces this with the real hash.
          vendorHash = pkgs.lib.fakeHash;

          meta = {
            description = "Transparently encrypt secret files in a git repository";
            mainProgram = "git-vault";
          };
        };

        devShells.default = pkgs.mkShell {
          buildInputs = [
            pkgs.go
            pkgs.golangci-lint
            pkgs.goreleaser
            pkgs.gofumpt
            pkgs.go-task
          ];
        };
      });
}
```

- [ ] **Step 2: Build once to discover the real vendorHash**

Run: `nix build`
Expected: fails with a hash mismatch error that prints the correct `vendorHash` value. Copy that value into `flake.nix`, replacing `pkgs.lib.fakeHash`.

- [ ] **Step 3: Build again to confirm it succeeds**

Run: `nix build`
Expected: succeeds and produces `./result/bin/git-vault`.

- [ ] **Step 4: Run flake check now that vendorHash is real**

Run: `nix flake check`
Expected: no errors. (Run this only after Step 3 succeeds — some Nix versions build `packages.default` as part of `flake check`, which would otherwise hit the same hash-mismatch failure Step 2 expects.)

- [ ] **Step 5: Commit**

```bash
git add flake.nix flake.lock
git commit -m "chore: add Nix flake with devShell and package output"
```

---

### Task 11: GitHub Actions CI workflow

**Files:**
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: `go test ./...`, `go build ./...`, golangci-lint (Task 9's `.golangci.yml`).

- [ ] **Step 1: Add the CI workflow**

Create `.github/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.26.5"
      - run: go build ./...
      - run: go test ./...

  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.26.5"
      - uses: golangci/golangci-lint-action@v6
        with:
          version: latest
```

- [ ] **Step 2: Verify the workflow YAML is well-formed**

Run: `python3 -c "import yaml, sys; yaml.safe_load(open('.github/workflows/ci.yml'))" && echo OK`
Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add lint, build, and test workflow"
```

---

### Task 12: goreleaser config and release workflow

**Files:**
- Create: `.goreleaser.yaml`
- Create: `.github/workflows/release.yml`

**Interfaces:**
- Consumes: `cli.Version` (Task 2), triggered by `.github/workflows/release.yml` on tag push.

- [ ] **Step 1: Add .goreleaser.yaml**

Create `.goreleaser.yaml`:

```yaml
version: 2

project_name: git-vault

builds:
  - id: git-vault
    main: ./cmd/git-vault
    binary: git-vault
    env:
      - CGO_ENABLED=0
    ldflags:
      - -s -w -X github.com/ducduyn31/git-vault/internal/cli.Version={{.Version}}
    goos:
      - linux
      - darwin
    goarch:
      - amd64
      - arm64

archives:
  - formats: [tar.gz]
    name_template: >-
      {{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}

checksum:
  name_template: "checksums.txt"

changelog:
  sort: asc
  filters:
    exclude:
      - "^docs:"
      - "^test:"
      - "^ci:"
```

- [ ] **Step 2: Verify the config is well-formed**

Run: `goreleaser check` (if goreleaser is installed locally, e.g. via `nix develop`) or `python3 -c "import yaml, sys; yaml.safe_load(open('.goreleaser.yaml'))" && echo OK` as a syntax-only fallback.
Expected: `goreleaser check` reports no errors, or `OK` from the fallback.

- [ ] **Step 3: Add the release workflow**

Create `.github/workflows/release.yml`:

```yaml
name: Release

on:
  push:
    tags:
      - "v*"

permissions:
  contents: write

jobs:
  goreleaser:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-go@v5
        with:
          go-version: "1.26.5"
      - uses: goreleaser/goreleaser-action@v6
        with:
          version: latest
          args: release --clean
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

- [ ] **Step 4: Verify the workflow YAML is well-formed**

Run: `python3 -c "import yaml, sys; yaml.safe_load(open('.github/workflows/release.yml'))" && echo OK`
Expected: `OK`

- [ ] **Step 5: Commit**

```bash
git add .goreleaser.yaml .github/workflows/release.yml
git commit -m "ci: add goreleaser config and tag-triggered release workflow"
```

---

## Final verification

- [ ] Run `go build ./...` — succeeds.
- [ ] Run `go test ./...` — every package `ok`.
- [ ] Run `go vet ./...` — no issues.
- [ ] Run `gofumpt -l .` — no files listed (everything formatted).
- [ ] If `golangci-lint` is available (e.g. via `nix develop`): run `task lint` — no issues.
- [ ] Run `git log --oneline` and confirm one commit per task above, in order.
