package auth

import (
	"testing"

	"golang.org/x/oauth2"
)

// A token response without an id_token must yield the "empty id_token" error,
// not a panic (matching the Apple/Microsoft providers on the same input).
func TestOIDCFetchRawUserInfoMissingIdToken(t *testing.T) {
	p := NewOIDCProvider()

	// JSON token-endpoint shape whose Raw map lacks "id_token"
	token := (&oauth2.Token{AccessToken: "x"}).WithExtra(map[string]any{"token_type": "Bearer"})

	_, err := p.FetchRawUserInfo(token)
	if err == nil {
		t.Fatal("expected an error for a token without id_token, got nil")
	}
	t.Logf("got error (good): %v", err)
}
