// Package ui renders git-vault's user-facing command output: leveled
// success/error messages and a colored table for the status command.
package ui

import (
	"fmt"
	"io"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"github.com/charmbracelet/log"
)

// New builds a logger for user-facing command output. Info-level calls
// render with a green checkmark instead of the word "INFO" — this is the
// success/confirmation path. Color is decided per-writer by
// charmbracelet/log's own terminal detection: a bytes.Buffer (as used in
// tests) or a redirected file renders plain text automatically, with no
// custom isatty check needed.
func New(w io.Writer) *log.Logger {
	l := log.NewWithOptions(w, log.Options{ReportTimestamp: false})
	styles := log.DefaultStyles()
	styles.Levels[log.InfoLevel] = lipgloss.NewStyle().SetString("✓").Foreground(lipgloss.Color("2"))
	l.SetStyles(styles)
	return l
}

// Error renders err in red as "✗ Error: <message>" to w. This is the single
// choke point for error styling — cmd/git-vault/main.go is its only caller;
// every other command keeps returning plain error values.
func Error(w io.Writer, err error) {
	l := log.NewWithOptions(w, log.Options{ReportTimestamp: false})
	styles := log.DefaultStyles()
	styles.Levels[log.ErrorLevel] = lipgloss.NewStyle().SetString("✗ Error:").Foreground(lipgloss.Color("1"))
	l.SetStyles(styles)
	l.Error(err.Error())
}

// Table renders a FILE/STATE table to w for the status command. The STATE
// column is colored per value: "encrypted" green, "plaintext" yellow,
// anything else (an error message) red.
func Table(w io.Writer, rows [][2]string) {
	re := lipgloss.NewRenderer(w)
	green := re.NewStyle().Foreground(lipgloss.Color("2"))
	yellow := re.NewStyle().Foreground(lipgloss.Color("3"))
	red := re.NewStyle().Foreground(lipgloss.Color("1"))

	t := table.New().Headers("FILE", "STATE")
	for _, row := range rows {
		state := row[1]
		var styled string
		switch state {
		case "encrypted":
			styled = green.Render(state)
		case "plaintext":
			styled = yellow.Render(state)
		default:
			styled = red.Render(state)
		}
		t.Row(row[0], styled)
	}
	fmt.Fprintln(w, t.Render())
}
