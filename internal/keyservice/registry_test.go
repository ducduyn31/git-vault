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
