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
