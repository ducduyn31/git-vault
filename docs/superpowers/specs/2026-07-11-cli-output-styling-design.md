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
dependencies; `golang.org/x/term` (already a dependency) is reused for
terminal detection.

```go
// internal/ui/ui.go
func ColorEnabled(w io.Writer) bool
func New(w io.Writer) *log.Logger   // success/warn logger, level styles restyled
func Error(w io.Writer, err error)  // single error-rendering entry point
func Table(rows [][2]string) string // FILE/STATE table for status
```

Key decisions:

1. **Per-command logger, not a package-level global.** Each `RunE` builds
   its logger from `cmd.OutOrStdout()` / `cmd.ErrOrStderr()`, matching the
   existing pattern of writing through cobra's writers. This is what lets
   tests keep using `cmd.SetOut(&bytes.Buffer{})` to capture output.

2. **Color is decided explicitly by git-vault, not left to library
   auto-detection.** `ColorEnabled(w)` returns true only if `w` is an
   `*os.File`, `term.IsTerminal(fd)` is true, and `NO_COLOR` is unset.
   Every other writer (a `bytes.Buffer` in tests, a pipe, a redirected
   file) renders plain, uncolored text. This is deliberately not delegated
   to charmbracelet's own detection, which ties color profile to the
   process's actual stdout rather than the specific writer passed in —
   relying on that would risk ANSI codes leaking into piped/test output.
   `ColorEnabled`'s result is used to pick a `lipgloss.Renderer` bound to
   that writer (`lipgloss.NewRenderer(w)`, with `.SetColorProfile(termenv.Ascii)`
   forced when disabled) and passed to both the logger's styles and the
   table renderer.

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

Existing tests assert exact output strings via `cmd.SetOut(&bytes.Buffer{})`.
Since a `bytes.Buffer` is never an `*os.File`, `ColorEnabled` returns false
for every existing test, so output stays plain text — but the text itself
changes (new checkmark-prefixed wording, new confirmation lines), so
existing assertions in `install_test.go`, `migrate_test.go`, `rotate_test.go`,
`status_test.go`, `encrypt_test.go`, and `track`'s (new) test need updating
to match. This is expected, not a regression.

A new `internal/ui` package gets its own unit tests covering:
- `ColorEnabled` returns false for a `bytes.Buffer`, true for a `*os.File`
  pointing at a real TTY is not practically testable in CI — test the
  `*os.File`-but-not-a-TTY case (e.g. a temp file) returns false, and that
  `NO_COLOR=1` forces false even when otherwise eligible.
- `Table` renders expected column alignment for a few sample rows.

## Out of scope / future

- No `--no-color` flag — `NO_COLOR` env var + TTY detection is enough.
- No debug/verbose logging mode — this is a display-polish change only.
- No changes to `clean`/`smudge`/`version` (see Scope above).
