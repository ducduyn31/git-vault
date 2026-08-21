// Package gitcmd shells out to the git binary for the plumbing git-vault
// needs but can't do itself: resolving pathspecs to tracked files and
// reading/writing filter driver settings in git config. Anything that
// parses or writes a file on its own belongs elsewhere (see
// internal/gitattr for .gitattributes).
package gitcmd

import (
	"fmt"
	"os/exec"
	"strings"
)

// TrackedFiles resolves .gitattributes patterns to the working-tree paths
// git itself considers tracked, using git's own pathspec matching rather
// than reimplementing gitignore-style globbing.
func TrackedFiles(patterns []string) ([]string, error) {
	args := append([]string{"ls-files", "--"}, patterns...)
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files: %w", err)
	}

	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" {
		return nil, nil
	}
	return strings.Split(trimmed, "\n"), nil
}

// SetConfig writes key=value to the repo's git config, or the user's
// global config when global is set.
func SetConfig(global bool, key, value string) error {
	out, err := exec.Command("git", configArgs(global, key, value)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("git %s: %w: %s", key, err, out)
	}
	return nil
}

// UnsetConfig removes key from git config, treating "key not set" (git's
// exit code 5) as success so uninstall stays idempotent.
func UnsetConfig(global bool, key string) error {
	out, err := exec.Command("git", configArgs(global, "--unset", key)...).CombinedOutput()
	if err == nil {
		return nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 5 {
		return nil
	}
	return fmt.Errorf("git %s: %w: %s", key, err, out)
}

// configArgs builds arguments for a Git config command, optionally targeting the global configuration.
func configArgs(global bool, rest ...string) []string {
	args := []string{"config"}
	if global {
		args = append(args, "--global")
	}
	return append(args, rest...)
}

// IndexBlob returns the raw (unfiltered) blob content git currently has
// staged for path, which is repo-root-relative — the same form git hands
// filter drivers as %f. The bool is false when path has no index entry;
// IndexBlob returns the raw staged blob for the repository-relative path.
// The boolean is true when the blob is read successfully and false when the
// path has no readable index entry or Git reports an error.
func IndexBlob(path string) ([]byte, bool) {
	out, err := exec.Command("git", "cat-file", "blob", ":"+path).Output()
	if err != nil {
		return nil, false
	}
	return out, true
}
