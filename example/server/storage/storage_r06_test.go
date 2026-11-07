package storage

// R06 characterization: for a policy-backed client_credentials client, the
// resource policy doubles as the default access audience when the token
// request carries no `resource` parameter. A client with
// allowedResources=[A,B] requesting no resource receives aud=[client,A,B];
// requesting A narrows it to aud=[client,A]. This pins the current behavior
// as a documented maintainer decision: an allowlist is not inherently an
// all-resources default, and a future policy may prefer the legacy [client]
// audience for resource-less requests. These tests change no behavior.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/oidc/v3/pkg/op"
)

const (
	r06resA = "https://a.example.com"
	r06resB = "https://b.example.com"
)

// r06IssueJWT returns the aud claim of a JWT access token issued for request.
func r06IssueJWT(t *testing.T, store *Storage, request op.TokenRequest) []string {
	t.Helper()
	token, err := op.CreateJWT(context.Background(), "http://test.example.com", request,
		time.Now().Add(time.Hour), "token-id", &Client{id: r05svc}, store)
	require.NoError(t, err)
	return decodeJWTAudience(t, token)
}

func TestR06NoResourceCCDefaultAudience(t *testing.T) {
	ctx := context.Background()

	t.Run("policy becomes the default audience without explicit resource", func(t *testing.T) {
		store := r05Store([]string{r06resA, r06resB})

		req, err := store.ClientCredentialsTokenRequest(ctx, r05svc, []string{"openid"})
		require.NoError(t, err)
		// No ValidateTokenRequestResources call: the request selects nothing.

		tokenID, _, err := store.CreateAccessToken(ctx, req)
		require.NoError(t, err)
		token := store.tokens[tokenID]
		require.NotNil(t, token)
		assert.Equal(t, []string{r05svc, r06resA, r06resB}, token.Audience,
			"pinned default: full policy is the audience when no resource is requested")
		assert.Equal(t, []string{r05svc, r06resA, r06resB}, r06IssueJWT(t, store, req),
			"JWT and opaque record agree on the default")
	})

	t.Run("explicit resource narrows the policy", func(t *testing.T) {
		store := r05Store([]string{r06resA, r06resB})

		req, err := store.ClientCredentialsTokenRequest(ctx, r05svc, []string{"openid"})
		require.NoError(t, err)
		require.NoError(t, op.ValidateTokenRequestResources([]string{r06resA}, req))

		tokenID, _, err := store.CreateAccessToken(ctx, req)
		require.NoError(t, err)
		assert.Equal(t, []string{r05svc, r06resA}, store.tokens[tokenID].Audience)
		assert.Equal(t, []string{r05svc, r06resA}, r06IssueJWT(t, store, req))
	})

	t.Run("client without policy keeps the legacy audience", func(t *testing.T) {
		store := r05Store(nil)

		req, err := store.ClientCredentialsTokenRequest(ctx, r05svc, []string{"openid"})
		require.NoError(t, err)

		tokenID, _, err := store.CreateAccessToken(ctx, req)
		require.NoError(t, err)
		assert.Equal(t, []string{r05svc}, store.tokens[tokenID].Audience)
	})
}
