package storage

// A01 reproduction: a historical refresh token granted before resource
// indicators existed (Resource=nil, Audience=[client,legacy-api]) must keep
// its access audience when refreshed without `resource`. The ID token stays
// addressed to the client, explicit narrowing still binds, and requesting a
// resource outside the (empty) grant stays refused.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

const (
	a01client = "web-app"
	a01legacy = "https://legacy.example.com/api"
	a01resA   = "https://a.example.com"
	a01resB   = "https://b.example.com"
)

func a01Store() *Storage {
	return NewStorageWithClients(
		NewUserStore("http://test.example.com"),
		map[string]*Client{a01client: WebClient(a01client, "secret")},
	)
}

// a01SeedRefreshToken stores a refresh record as-is and returns its token.
func a01SeedRefreshToken(store *Storage, id string, audience, resources []string) string {
	store.refreshTokens[id] = &RefreshToken{
		ID:            id,
		Token:         id,
		ApplicationID: a01client,
		Audience:      audience,
		UserID:        "id1",
		Scopes:        []string{"openid", "offline_access"},
		Expiration:    time.Now().Add(time.Hour),
		AuthTime:      time.Now(),
		Resource:      resources,
	}
	return id
}

// a01Refresh drives the real refresh issuance path and returns the access
// token ID, the rotated refresh token and the request (for JWT issuance).
func a01Refresh(t *testing.T, store *Storage, refreshToken string, scopes, resources []string) (string, string, op.TokenRequest) {
	t.Helper()
	ctx := context.Background()
	req, err := store.TokenRequestByRefreshToken(ctx, refreshToken)
	require.NoError(t, err)
	require.NoError(t, op.ValidateRefreshTokenScopes(scopes, req))
	require.NoError(t, op.ValidateTokenRequestResources(resources, req))
	accessID, newRefresh, _, err := store.CreateAccessAndRefreshTokens(ctx, req, refreshToken)
	require.NoError(t, err)
	return accessID, newRefresh, req
}

func TestA01LegacyRefreshKeepsHistoricalAudience(t *testing.T) {
	t.Run("refresh without resource keeps [client, legacy-api]", func(t *testing.T) {
		store := a01Store()
		refreshToken := a01SeedRefreshToken(store, "legacy-rt",
			[]string{a01client, a01legacy}, nil)

		accessID, _, req := a01Refresh(t, store, refreshToken,
			[]string{"openid", "offline_access"}, nil)

		assert.Equal(t, []string{a01client, a01legacy}, r02IssueJWT(t, store, req),
			"JWT access aud must keep the historical audience")
		assert.Equal(t, []string{a01client, a01legacy}, store.tokens[accessID].Audience,
			"opaque record must keep the historical audience")
		idReq, ok := req.(op.IDTokenRequest)
		require.True(t, ok)
		assert.Equal(t, []string{a01client}, r02IssueIDAudience(t, store, idReq),
			"ID token stays addressed to the client")
	})

	t.Run("rotation preserves the historical audience across chained refreshes", func(t *testing.T) {
		store := a01Store()
		refreshToken := a01SeedRefreshToken(store, "legacy-rt",
			[]string{a01client, a01legacy}, nil)

		_, rotated, _ := a01Refresh(t, store, refreshToken,
			[]string{"openid", "offline_access"}, nil)
		accessID, _, req := a01Refresh(t, store, rotated,
			[]string{"openid", "offline_access"}, nil)

		assert.Equal(t, []string{a01client, a01legacy}, r02IssueJWT(t, store, req))
		assert.Equal(t, []string{a01client, a01legacy}, store.tokens[accessID].Audience)
	})

	t.Run("explicit resource on a legacy grant stays refused", func(t *testing.T) {
		store := a01Store()
		refreshToken := a01SeedRefreshToken(store, "legacy-rt",
			[]string{a01client, a01legacy}, nil)

		req, err := store.TokenRequestByRefreshToken(context.Background(), refreshToken)
		require.NoError(t, err)
		err = op.ValidateTokenRequestResources([]string{a01resA}, req)
		require.Error(t, err)
		assert.Equal(t, oidc.InvalidTarget, err.(*oidc.Error).ErrorType,
			"no silent audience extension on a resourceless grant")
	})

	t.Run("resource grant narrowing still binds (no regression)", func(t *testing.T) {
		store := a01Store()
		refreshToken := a01SeedRefreshToken(store, "res-rt",
			[]string{a01client, a01resA}, []string{a01resA})

		accessID, _, req := a01Refresh(t, store, refreshToken,
			[]string{"openid", "offline_access"}, []string{a01resA})

		assert.Equal(t, []string{a01client, a01resA}, r02IssueJWT(t, store, req))
		assert.Equal(t, []string{a01client, a01resA}, store.tokens[accessID].Audience)
	})

	t.Run("resource grant refresh without resource keeps the full grant (no regression)", func(t *testing.T) {
		store := a01Store()
		refreshToken := a01SeedRefreshToken(store, "res-rt",
			[]string{a01client, a01resA}, []string{a01resA})

		accessID, _, req := a01Refresh(t, store, refreshToken,
			[]string{"openid", "offline_access"}, nil)

		assert.Equal(t, []string{a01client, a01resA}, r02IssueJWT(t, store, req))
		assert.Equal(t, []string{a01client, a01resA}, store.tokens[accessID].Audience)
	})

	t.Run("refresh outside the grant stays refused", func(t *testing.T) {
		store := a01Store()
		refreshToken := a01SeedRefreshToken(store, "res-rt",
			[]string{a01client, a01resA}, []string{a01resA})

		req, err := store.TokenRequestByRefreshToken(context.Background(), refreshToken)
		require.NoError(t, err)
		err = op.ValidateTokenRequestResources([]string{a01resB}, req)
		require.Error(t, err)
		assert.Equal(t, oidc.InvalidTarget, err.(*oidc.Error).ErrorType)
	})
}
