package cli

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCleanCmd_ThenSmudgeCmd_RoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	runInstall(t)

	original := "password: hunter2\n"

	cleanCmd := NewRootCmd()
	sealed := &bytes.Buffer{}
	cleanCmd.SetIn(strings.NewReader(original))
	cleanCmd.SetOut(sealed)
	cleanCmd.SetArgs([]string{"clean", "secret.yaml"})
	require.NoError(t, cleanCmd.Execute())

	require.NotContains(t, sealed.String(), "hunter2")
	require.Contains(t, sealed.String(), "password: ENC[")

	smudgeCmd := NewRootCmd()
	opened := &bytes.Buffer{}
	smudgeCmd.SetIn(bytes.NewReader(sealed.Bytes()))
	smudgeCmd.SetOut(opened)
	smudgeCmd.SetArgs([]string{"smudge", "secret.yaml"})
	require.NoError(t, smudgeCmd.Execute())

	require.Equal(t, original, opened.String())
}

// stageBlob writes content into the object store and stages it at path,
// via plumbing — `git add` would shell out to the git-vault binary, which
// isn't built during tests.
func stageBlob(t *testing.T, path string, content []byte) string {
	t.Helper()
	hash := exec.Command("git", "hash-object", "-w", "--stdin")
	hash.Stdin = bytes.NewReader(content)
	out, err := hash.Output()
	require.NoError(t, err)
	sha := strings.TrimSpace(string(out))
	require.NoError(t, exec.Command("git", "update-index", "--add", "--cacheinfo", "100644,"+sha+","+path).Run())
	return sha
}

func runClean(t *testing.T, path string, in []byte) []byte {
	t.Helper()
	cmd := NewRootCmd()
	out := &bytes.Buffer{}
	cmd.SetIn(bytes.NewReader(in))
	cmd.SetOut(out)
	cmd.SetArgs([]string{"clean", path})
	require.NoError(t, cmd.Execute())
	return out.Bytes()
}

func TestCleanCmd_UnchangedPlaintext_ReemitsStagedBlob(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	runInstall(t)

	plaintext := []byte("password: hunter2\n")
	sealed := runClean(t, "secret.yaml", plaintext)
	stageBlob(t, "secret.yaml", sealed)

	// Re-cleaning identical plaintext must reproduce the staged bytes
	// exactly, or git reports the file as permanently modified.
	require.Equal(t, sealed, runClean(t, "secret.yaml", plaintext))
}

func TestCleanCmd_ChangedPlaintext_SealsFresh(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	runInstall(t)

	sealed := runClean(t, "secret.yaml", []byte("password: hunter2\n"))
	stageBlob(t, "secret.yaml", sealed)

	reclean := runClean(t, "secret.yaml", []byte("password: hunter3\n"))
	require.NotEqual(t, sealed, reclean)
	require.NotContains(t, string(reclean), "hunter3")
}

func TestCleanCmd_PlaintextStagedBlob_StillSeals(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	runInstall(t)

	// A file staged as plaintext before install: the shortcut must not
	// pass it through, or it would never get encrypted.
	plaintext := []byte("password: hunter2\n")
	stageBlob(t, "secret.yaml", plaintext)

	out := runClean(t, "secret.yaml", plaintext)
	require.NotContains(t, string(out), "hunter2")
	require.Contains(t, string(out), "password: ENC[")
}

func TestCleanCmd_BinaryFormat_UnchangedPlaintext_ReemitsStagedBlob(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	chdirTemp(t)
	runInstall(t)

	// Extensionless key file: the binary store, not YAML — the format
	// that motivated the fix.
	const path = "keys/id_ed25519"
	plaintext := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA\x00\x01\n-----END OPENSSH PRIVATE KEY-----\n")

	sealed := runClean(t, path, plaintext)
	require.NotContains(t, string(sealed), "OPENSSH")
	stageBlob(t, path, sealed)

	require.Equal(t, sealed, runClean(t, path, plaintext))
}
