# CLI output styling design

## Problem

git-vault's commands write output via bare `fmt.Fprintf`/`fmt.Fprintln` to
`cmd.OutOrStdout()`, and `main.go` prints errors via a plain
`fmt.Fprintln(os.Stderr, err)`. There's no color, no visual distinction
between success/warning/error, and `status`'s file-list is an unaligned
tab-separated dump. Three commands (`track`, `encrypt`, `decrypt`) print
nothing at all on success.

This is a polish pass: make output easier to scan, not a diagnostics/verbose-
logging feature. No new flags, no debug/verbose mode.

## Scope

**In scope:** `install`, `track`, `migrate`, `rotate`, `encrypt`, `decrypt`,
`status`, `login`, and the single error-printing path in `main.go`. `login`
needs no direct code change — it only ever returns a plain "not
implemented" error today, which is already covered by the centralized
error-styling path in `main.go`.

**Explicitly out of scope:**
- `version` — prints a bare version string only; must stay
  machine-parseable for scripts, no styling, no logger.
- `clean` / `smudge` — these stream raw file content to `cmd.OutOrStdout()`
  as git filter-driver entry points. That stream must never be touched by
  logging output. No changes here.
- `uninstall` — not currently wired into the CLI; out of scope for this
  change.

## Architecture

A new `internal/ui` package wraps `charmbracelet/log` (leveled logger) and
`charmbracelet/lipgloss` (styles + table layout). Two new direct
dependencies.

```go
// internal/ui/ui.go
func New(w io.Writer) *log.Logger   // success/warn logger, level styles restyled
func Error(w io.Writer, err error)  // single error-rendering entry point
func Table(w io.Writer, rows [][2]string) // renders FILE/STATE table for status
```

Key decisions:

1. **Per-command logger, not a package-level global.** Each `RunE` builds
   its logger from `cmd.OutOrStdout()` / `cmd.ErrOrStderr()`, matching the
   existing pattern of writing through cobra's writers. This is what lets
   tests keep using `cmd.SetOut(&bytes.Buffer{})` to capture output.

2. **Color/TTY detection is delegated to the libraries — verified, not
   assumed.** `charmbracelet/log` and `lipgloss` both detect color support
   per the specific `io.Writer` passed in (via the shared
   `charmbracelet/colorprofile` detection, which checks whether the writer
   is a terminal file descriptor, and honors `NO_COLOR`). This was
   confirmed with a throwaway spike: `log.New(buf).Info(...)` and
   `lipgloss.NewRenderer(buf).NewStyle()...Render(...)` against a
   `bytes.Buffer` both produced plain text with zero ANSI escape codes.
   No custom isatty/`NO_COLOR` wrapper is needed — writing one would just
   reimplement what the libraries already do correctly per-writer.

3. **Errors funnel through one place.** Commands keep returning plain
   `error` values exactly as today (`fmt.Errorf("git vault x: %w", err)`,
   etc.) — no change to error construction. Only `cmd/git-vault/main.go`
   changes, swapping `fmt.Fprintln(os.Stderr, err)` for
   `ui.Error(os.Stderr, err)`. This is the single choke point for error
   styling; no per-command changes needed for errors.

## Styling rules

| Kind | Style | Where |
|---|---|---|
| Success/confirmation | Info level, restyled as green `✓ ` prefix (no "INFO" text) | install, migrate, rotate, status header line, new track/encrypt/decrypt confirmations |
| Warning | Yellow, Warn level | status per-file `error: %v` when `IsSealed` fails |
| Error | Red `✗ Error: <message>` | main.go, single path |
| Table | `lipgloss/table`, header `FILE  STATE`, colored state cell | status |

Status table state coloring: `encrypted` → green, `plaintext` → yellow,
`error: ...` → red.

## New confirmation messages

Commands that currently print nothing on success gain one line, for
consistency with install/migrate/rotate:

- `track <pattern>` → `Tracking secrets/*.yaml`
- `encrypt <file>` → `Sealed secrets/prod.yaml`
- `decrypt <file>` → `Opened secrets/prod.yaml`

## Testing

Existing tests write to a `bytes.Buffer` via `cmd.SetOut(...)`, so per the
spike above, output renders in plain text (no ANSI codes) exactly as it
does today. Most existing assertions use `require.Contains` on a substring
(`"Migrated 1 file"`, `"Recipient: passphrase:shared"`, etc.), which the new
`✓ ` prefix doesn't break — confirmed by spiking the exact rendering of a
multi-line `Info` call. The one exception: `status_test.go`'s two
`require.Contains(t, out.String(), "secret.yaml\tplaintext")`-style
assertions check the current tab-separated format directly, which the new
table replaces — those two assertions need updating to match the table
output. `version_test.go`'s `require.Equal(t, "dev\n", ...)` is unaffected
since `version` is out of scope.

A new `internal/ui` package gets its own unit tests covering:
- `New(buf).Info("msg")` renders `"✓ msg\n"` with no ANSI codes when `buf`
  is a `bytes.Buffer`.
- `Error(buf, err)` renders `"✗ Error: <err.Error()>\n"`.
- `Table` renders the expected header and colored-free (buffer target)
  column output for a few sample rows, including the encrypted/plaintext/
  error coloring branch selection (verified by checking which style
  function was applied is hard to assert directly on a buffer since color
  is off there — instead assert the row *text* content and column
  alignment; color branch selection is exercised implicitly and re-verified
  by manual TTY testing during the verify step, not by an automated color
  assertion).

## Out of scope / future

- No `--no-color` flag — `NO_COLOR` env var + TTY detection is enough.
- No debug/verbose logging mode — this is a display-polish change only.
- No changes to `clean`/`smudge`/`version` (see Scope above).
