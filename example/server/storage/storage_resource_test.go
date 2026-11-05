package storage

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// decodeJWTAudience returns the aud claim of an issued JWT without verifying
// its signature.
func decodeJWTAudience(t *testing.T, token string) []string {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims struct {
		Audience oidc.Audience `json:"aud"`
	}
	require.NoError(t, json.Unmarshal(payload, &claims))
	return []string(claims.Audience)
}

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

// TestClientCredentialsResourcePolicy shows the client_credentials resource
// contract: a service client with an explicit resource policy reports it as the
// grant, so a token request for an allowed resource succeeds and binds the
// access audience, while anything else fails with invalid_target. A service
// client without policy cannot honor an explicit resource under strict
// enforcement.
func TestClientCredentialsResourcePolicy(t *testing.T) {
	const (
		mcp = "https://mcp.example.com/mcp"
		api = "https://api.example.com"
	)
	ctx := context.Background()
	store := NewStorage(NewUserStore("http://test.example.com"))
	store.serviceUsers["rs-svc"] = &Client{
		id:     "rs-svc",
		secret: "verysecret",
		grantTypes: []oidc.GrantType{
			oidc.GrantTypeClientCredentials,
		},
		accessTokenType:  op.AccessTokenTypeBearer,
		allowedResources: []string{mcp},
	}

	t.Run("allowed resource succeeds and binds the audience", func(t *testing.T) {
		request, err := store.ClientCredentialsTokenRequest(ctx, "rs-svc", []string{"scope"})
		require.NoError(t, err)
		assert.Equal(t, "rs-svc", request.GetSubject())
		require.NoError(t, op.ValidateTokenRequestResourcesStrict([]string{mcp}, request))
		aud, ok := request.(op.AccessTokenAudienceRequest)
		require.True(t, ok)
		assert.Equal(t, []string{"rs-svc", mcp}, aud.GetAccessTokenAudience())
	})

	t.Run("resource outside the policy fails", func(t *testing.T) {
		request, err := store.ClientCredentialsTokenRequest(ctx, "rs-svc", []string{"scope"})
		require.NoError(t, err)
		err = op.ValidateTokenRequestResourcesStrict([]string{api}, request)
		require.Error(t, err)
		var oidcErr *oidc.Error
		require.ErrorAs(t, err, &oidcErr)
		assert.Equal(t, oidc.InvalidTarget, oidcErr.ErrorType)
	})

	t.Run("service client without policy cannot honor an explicit resource", func(t *testing.T) {
		request, err := store.ClientCredentialsTokenRequest(ctx, "sid1", []string{"scope"})
		require.NoError(t, err)
		err = op.ValidateTokenRequestResourcesStrict([]string{mcp}, request)
		require.Error(t, err)
		var oidcErr *oidc.Error
		require.ErrorAs(t, err, &oidcErr)
		assert.Equal(t, oidc.InvalidTarget, oidcErr.ErrorType)
	})
}

// TestAccessAndIDTokenAudiencesSeparated is a regression test for F05: resource
// indicators bind the access token audience to the effective resource selection,
// while ID tokens stay addressed to the OAuth client alone. It issues real JWTs
// through op.CreateJWT and op.CreateIDToken and reads back their aud claims.
func TestAccessAndIDTokenAudiencesSeparated(t *testing.T) {
	const (
		mcp = "https://mcp.example.com/mcp"
		api = "https://api.example.com"
	)
	ctx := context.Background()
	issuer := "http://test.example.com"
	store := NewStorage(NewUserStore(issuer))
	client := &Client{id: "web"}

	authReq := authRequestToInternal(&oidc.AuthRequest{
		ClientID: "web",
		Scopes:   []string{"openid"},
		Resource: []string{mcp, api},
	}, "id1")
	authReq.SetCurrentResources([]string{mcp})

	refreshReq := RefreshTokenRequestFromBusiness(&RefreshToken{
		ApplicationID: "web",
		UserID:        "id1",
		Scopes:        []string{"openid"},
		AuthTime:      time.Now(),
		AMR:           []string{"pwd"},
		Audience:      []string{"web"},
		Resource:      []string{mcp, api},
	})
	refreshReq.(op.CurrentResourceSetter).SetCurrentResources([]string{api})

	for _, request := range []struct {
		name        string
		request     op.IDTokenRequest
		wantAccess  []string
		description string
	}{
		{"authorization code request", authReq, []string{"web", mcp}, "narrowed to mcp"},
		{"refresh token request", refreshReq, []string{"web", api}, "narrowed to api"},
	} {
		t.Run(request.name, func(t *testing.T) {
			tokenRequest, ok := request.request.(op.TokenRequest)
			require.True(t, ok)

			accessToken, err := op.CreateJWT(ctx, issuer, tokenRequest, time.Now().Add(time.Hour), "token-id", client, store)
			require.NoError(t, err)
			assert.Equal(t, request.wantAccess, decodeJWTAudience(t, accessToken),
				"access token audience (%s)", request.description)

			idToken, err := op.CreateIDToken(ctx, issuer, request.request, time.Hour, "", "", store, client)
			require.NoError(t, err)
			assert.Equal(t, []string{"web"}, decodeJWTAudience(t, idToken),
				"ID token stays addressed to the client alone")
		})
	}
}
