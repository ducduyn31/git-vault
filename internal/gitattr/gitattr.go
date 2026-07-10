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
	defer func() { _ = f.Close() }()

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
