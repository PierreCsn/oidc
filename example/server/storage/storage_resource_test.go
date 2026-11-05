package storage

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// TestAuthCodeRefreshKeepsFullResourceGrant is a regression test for F03:
// in the authorization_code case where the token request narrows the granted
// resources to a subset, the access token is issued for that subset (RFC 8707
// section 2.2) while the refresh token stays bound to the full original grant,
// so a later refresh may target any originally granted resource.
func TestAuthCodeRefreshKeepsFullResourceGrant(t *testing.T) {
	const (
		mcp = "https://mcp.example.com/mcp"
		api = "https://api.example.com"
	)
	ctx := context.Background()
	store := NewStorage(NewUserStore("http://test.example.com"))

	authReq := authRequestToInternal(&oidc.AuthRequest{
		ClientID: "web",
		Resource: []string{mcp, api},
	}, "id1")

	// code exchange narrowed down to a single resource
	require.NoError(t, op.ValidateTokenRequestResources([]string{mcp}, authReq))
	accessTokenID, refreshToken, _, err := store.CreateAccessAndRefreshTokens(ctx, authReq, "")
	require.NoError(t, err)

	accessToken, ok := store.tokens[accessTokenID]
	require.True(t, ok, "access token must be stored")
	assert.Equal(t, []string{mcp}, accessToken.Resource, "access token is issued for the narrowed subset")

	stored, ok := store.refreshTokens[refreshToken]
	require.True(t, ok, "refresh token must be stored")
	require.Equal(t, []string{mcp, api}, stored.Resource, "refresh token stays bound to the full original grant")

	// a later refresh may therefore target the other originally granted resource
	refreshReq, err := store.TokenRequestByRefreshToken(ctx, refreshToken)
	require.NoError(t, err)
	require.NoError(t, op.ValidateTokenRequestResources([]string{api}, refreshReq),
		"refresh to another originally granted resource must be accepted")
}

// TestRefreshNarrowingPreservesStoredGrant is a regression test for F04:
// narrowing a refresh request to a subset selects that subset for the new
// access token, but must not rewrite the persisted refresh token grant, so
// rotation preserves the full grant and later refreshes may target any
// originally granted resource.
func TestRefreshNarrowingPreservesStoredGrant(t *testing.T) {
	const (
		mcp = "https://mcp.example.com/mcp"
		api = "https://api.example.com"
	)
	ctx := context.Background()
	store := NewStorage(NewUserStore("http://test.example.com"))

	authReq := authRequestToInternal(&oidc.AuthRequest{
		ClientID: "web",
		Resource: []string{mcp, api},
	}, "id1")
	_, refreshToken, _, err := store.CreateAccessAndRefreshTokens(ctx, authReq, "")
	require.NoError(t, err)

	// first refresh narrowed down to a single resource, with rotation
	refreshReq, err := store.TokenRequestByRefreshToken(ctx, refreshToken)
	require.NoError(t, err)
	require.NoError(t, op.ValidateTokenRequestResources([]string{mcp}, refreshReq))
	accessTokenID, rotatedRefreshToken, _, err := store.CreateAccessAndRefreshTokens(ctx, refreshReq, refreshToken)
	require.NoError(t, err)

	accessToken, ok := store.tokens[accessTokenID]
	require.True(t, ok, "access token must be stored")
	assert.Equal(t, []string{mcp}, accessToken.Resource, "access token is issued for the narrowed subset")

	rotated, ok := store.refreshTokens[rotatedRefreshToken]
	require.True(t, ok, "rotated refresh token must be stored")
	require.Equal(t, []string{mcp, api}, rotated.Resource,
		"rotation preserves the full original grant instead of the narrowed subset")

	// a later refresh may therefore target the other originally granted resource
	refreshReq2, err := store.TokenRequestByRefreshToken(ctx, rotatedRefreshToken)
	require.NoError(t, err)
	require.NoError(t, op.ValidateTokenRequestResources([]string{api}, refreshReq2),
		"refresh to another originally granted resource must be accepted after rotation")
}
