package awskmstest

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFakeServer_EncryptDecrypt_RoundTrip(t *testing.T) {
	hc, _, cleanup, err := NewFakeServer()
	require.NoError(t, err)
	defer cleanup()

	encBody, err := json.Marshal(map[string]any{
		"KeyId":     "arn:aws:kms:us-east-1:111111111111:key/test",
		"Plaintext": []byte("sops data key"),
	})
	require.NoError(t, err)

	var encOut struct{ CiphertextBlob []byte }
	doFakeRequest(t, hc, "TrentService.Encrypt", encBody, &encOut)
	require.NotEqual(t, "sops data key", string(encOut.CiphertextBlob))

	decBody, err := json.Marshal(map[string]any{"CiphertextBlob": encOut.CiphertextBlob})
	require.NoError(t, err)

	var decOut struct{ Plaintext []byte }
	doFakeRequest(t, hc, "TrentService.Decrypt", decBody, &decOut)
	require.Equal(t, "sops data key", string(decOut.Plaintext))
}

func TestFakeServer_Decrypt_TamperedCiphertextFails(t *testing.T) {
	hc, _, cleanup, err := NewFakeServer()
	require.NoError(t, err)
	defer cleanup()

	decBody, err := json.Marshal(map[string]any{"CiphertextBlob": []byte("not a real wrapped key")})
	require.NoError(t, err)

	resp := postFakeRequest(t, hc, "TrentService.Decrypt", decBody)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func postFakeRequest(t *testing.T, hc *http.Client, target string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "https://kms.us-east-1.amazonaws.com/", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("X-Amz-Target", target)
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	resp, err := hc.Do(req)
	require.NoError(t, err)
	return resp
}

func doFakeRequest(t *testing.T, hc *http.Client, target string, body []byte, out any) {
	t.Helper()
	resp := postFakeRequest(t, hc, target, body)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, out))
}
