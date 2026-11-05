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

// decodeJWTClientID returns the client_id claim of an issued JWT without
// verifying its signature.
func decodeJWTClientID(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims struct {
		ClientID string `json:"client_id"`
	}
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims.ClientID
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
		assert.Equal(t, []string{mcp}, aud.GetAccessTokenAudience())
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
		{"authorization code request", authReq, []string{mcp}, "narrowed to mcp"},
		{"refresh token request", refreshReq, []string{api}, "narrowed to api"},
	} {
		t.Run(request.name, func(t *testing.T) {
			tokenRequest, ok := request.request.(op.TokenRequest)
			require.True(t, ok)

			accessToken, err := op.CreateJWT(ctx, issuer, tokenRequest, time.Now().Add(time.Hour), "token-id", client, store)
			require.NoError(t, err)
			assert.Equal(t, request.wantAccess, decodeJWTAudience(t, accessToken),
				"access token audience (%s)", request.description)
			assert.Equal(t, "web", decodeJWTClientID(t, accessToken),
				"client stays identified by the client_id claim")

			idToken, err := op.CreateIDToken(ctx, issuer, request.request, time.Hour, "", "", store, client)
			require.NoError(t, err)
			assert.Equal(t, []string{"web"}, decodeJWTAudience(t, idToken),
				"ID token stays addressed to the client alone")
		})
	}
}

// TestStoredAudienceMatchesJWTAudience shows that opaque token records persist
// the same access audience JWTs carry for the same request, across narrowing
// and refresh rotation, and that resourceless flows keep the client audience.
func TestStoredAudienceMatchesJWTAudience(t *testing.T) {
	const (
		mcp = "https://mcp.example.com/mcp"
		api = "https://api.example.com"
	)
	ctx := context.Background()
	issuer := "http://test.example.com"
	store := NewStorage(NewUserStore(issuer))
	client := &Client{id: "web"}

	issueJWT := func(t *testing.T, request op.TokenRequest) []string {
		t.Helper()
		token, err := op.CreateJWT(ctx, issuer, request, time.Now().Add(time.Hour), "token-id", client, store)
		require.NoError(t, err)
		return decodeJWTAudience(t, token)
	}

	authReq := authRequestToInternal(&oidc.AuthRequest{
		ClientID: "web",
		Scopes:   []string{"openid"},
		Resource: []string{mcp, api},
	}, "id1")
	require.NoError(t, op.ValidateTokenRequestResources([]string{mcp}, authReq))
	accessTokenID, refreshToken, _, err := store.CreateAccessAndRefreshTokens(ctx, authReq, "")
	require.NoError(t, err)
	assert.Equal(t, []string{mcp}, store.tokens[accessTokenID].Audience)
	assert.Equal(t, issueJWT(t, authReq), store.tokens[accessTokenID].Audience,
		"opaque record carries the JWT audience")

	refreshReq, err := store.TokenRequestByRefreshToken(ctx, refreshToken)
	require.NoError(t, err)
	require.NoError(t, op.ValidateTokenRequestResources([]string{api}, refreshReq))
	rotatedID, _, _, err := store.CreateAccessAndRefreshTokens(ctx, refreshReq, refreshToken)
	require.NoError(t, err)
	assert.Equal(t, []string{api}, store.tokens[rotatedID].Audience)
	tokenRequest, ok := refreshReq.(op.TokenRequest)
	require.True(t, ok)
	assert.Equal(t, issueJWT(t, tokenRequest), store.tokens[rotatedID].Audience,
		"rotated opaque record carries the JWT audience")

	legacyReq := authRequestToInternal(&oidc.AuthRequest{
		ClientID: "web",
		Scopes:   []string{"openid"},
	}, "id1")
	legacyID, _, _, err := store.CreateAccessAndRefreshTokens(ctx, legacyReq, "")
	require.NoError(t, err)
	assert.Equal(t, []string{"web"}, store.tokens[legacyID].Audience)
	assert.Equal(t, []string{"web"}, issueJWT(t, legacyReq))
}

// TestDeviceTokenAudiencesSeparated issues real JWTs for a narrowed device
// authorization state: the access token audience holds the selected resource
// alone while the ID token stays addressed to the client.
func TestDeviceTokenAudiencesSeparated(t *testing.T) {
	const (
		mcp = "https://mcp.example.com/mcp"
		api = "https://api.example.com"
	)
	ctx := context.Background()
	issuer := "http://test.example.com"
	store := NewStorage(NewUserStore(issuer))
	client := &Client{id: "device"}

	state := &op.DeviceAuthorizationState{
		ClientID: "device",
		Scopes:   []string{"openid"},
		Subject:  "id1",
		AuthTime: time.Now(),
		AMR:      []string{"pwd"},
		Resource: []string{mcp, api},
	}
	require.NoError(t, op.ValidateTokenRequestResources([]string{mcp}, state))

	accessToken, err := op.CreateJWT(ctx, issuer, state, time.Now().Add(time.Hour), "token-id", client, store)
	require.NoError(t, err)
	assert.Equal(t, []string{mcp}, decodeJWTAudience(t, accessToken))
	assert.Equal(t, "device", decodeJWTClientID(t, accessToken))

	idToken, err := op.CreateIDToken(ctx, issuer, state, time.Hour, "", "", store, client)
	require.NoError(t, err)
	assert.Equal(t, []string{"device"}, decodeJWTAudience(t, idToken))
}

// TestIntrospectionAuthorizesByResourceMapping shows that introspection of a
// resource token succeeds for the mapped resource server and the issuing
// client only: any other caller, including a server mapped to another
// resource, learns nothing. Resourceless tokens keep the historical rule.
func TestIntrospectionAuthorizesByResourceMapping(t *testing.T) {
	const (
		mcp = "https://mcp.example.com/mcp"
		api = "https://api.example.com"
	)
	RegisterClients(
		&Client{id: "mcp-rs", secret: "secret", allowedResources: []string{mcp}},
		&Client{id: "api-rs", secret: "secret", allowedResources: []string{api}},
		&Client{id: "other-rs", secret: "secret", allowedResources: []string{"https://other.example.com"}},
	)
	ctx := context.Background()
	store := NewStorage(NewUserStore("http://test.example.com"))

	authReq := authRequestToInternal(&oidc.AuthRequest{
		ClientID: "web",
		Scopes:   []string{"openid"},
		Resource: []string{mcp, api},
	}, "id1")
	require.NoError(t, op.ValidateTokenRequestResources([]string{mcp}, authReq))
	resourceTokenID, _, _, err := store.CreateAccessAndRefreshTokens(ctx, authReq, "")
	require.NoError(t, err)

	legacyReq := authRequestToInternal(&oidc.AuthRequest{
		ClientID: "web",
		Scopes:   []string{"openid"},
	}, "id1")
	legacyTokenID, _, _, err := store.CreateAccessAndRefreshTokens(ctx, legacyReq, "")
	require.NoError(t, err)

	introspect := func(t *testing.T, tokenID, caller string) (*oidc.IntrospectionResponse, error) {
		t.Helper()
		response := new(oidc.IntrospectionResponse)
		err := store.SetIntrospectionFromToken(ctx, response, tokenID, "id1", caller)
		return response, err
	}

	t.Run("mapped resource server learns the authorized audience", func(t *testing.T) {
		response, err := introspect(t, resourceTokenID, "mcp-rs")
		require.NoError(t, err)
		assert.Equal(t, oidc.Audience{mcp}, response.Audience)
		assert.Equal(t, "web", response.ClientID)
	})

	t.Run("server mapped to another resource learns nothing", func(t *testing.T) {
		_, err := introspect(t, resourceTokenID, "api-rs")
		require.Error(t, err)
		_, err = introspect(t, resourceTokenID, "other-rs")
		require.Error(t, err)
	})

	t.Run("unmapped caller learns nothing", func(t *testing.T) {
		_, err := introspect(t, resourceTokenID, "unknown-rs")
		require.Error(t, err)
	})

	t.Run("issuing client keeps introspecting its token", func(t *testing.T) {
		response, err := introspect(t, resourceTokenID, "web")
		require.NoError(t, err)
		assert.Equal(t, oidc.Audience{mcp}, response.Audience)
	})

	t.Run("resourceless token keeps the historical rule", func(t *testing.T) {
		response, err := introspect(t, legacyTokenID, "web")
		require.NoError(t, err)
		assert.Equal(t, oidc.Audience{"web"}, response.Audience)
		_, err = introspect(t, legacyTokenID, "mcp-rs")
		require.Error(t, err)
	})
}
