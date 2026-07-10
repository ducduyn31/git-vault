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
