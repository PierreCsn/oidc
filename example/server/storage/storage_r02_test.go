package storage

// R02 reproduction: for the same token request, the JWT access token audience
// (bound to the effective RFC 8707 resource selection through
// GetAccessTokenAudience) and the persisted opaque record audience must agree,
// and introspection must expose that effective audience to authorized callers
// only. The canonical case is a web client asking for resource A: the JWT aud
// is [web-app, A], so the opaque record and the introspection response must
// carry [web-app, A] as well.

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
	r02client = "web-app"
	r02resA   = "https://a.example.com"
	r02resB   = "https://b.example.com"
)

// r02Store returns a Storage holding the issuing web client and two resource
// server clients, each explicitly mapped to the resource URI it serves.
func r02Store() *Storage {
	web := WebClient(r02client, "secret")
	rsA := &Client{id: "rs-a", secret: "secret", allowedResources: []string{r02resA}}
	rsB := &Client{id: "rs-b", secret: "secret", allowedResources: []string{r02resB}}
	return NewStorageWithClients(
		NewUserStore("http://test.example.com"),
		map[string]*Client{r02client: web, "rs-a": rsA, "rs-b": rsB},
	)
}

// r02ServiceStore registers serviceUserID as a client_credentials client with
// the given resource policy on top of r02Store.
func r02ServiceStore(serviceUserID string, policy []string) *Storage {
	store := r02Store()
	store.serviceUsers[serviceUserID] = &Client{
		id:               serviceUserID,
		secret:           "verysecret",
		grantTypes:       []oidc.GrantType{oidc.GrantTypeClientCredentials},
		accessTokenType:  op.AccessTokenTypeBearer,
		allowedResources: policy,
	}
	return store
}

// r02IssueJWT issues a JWT access token for request and returns its aud claim.
func r02IssueJWT(t *testing.T, store *Storage, request op.TokenRequest) []string {
	t.Helper()
	token, err := op.CreateJWT(context.Background(), "http://test.example.com", request,
		time.Now().Add(time.Hour), "token-id", &Client{id: r02client}, store)
	require.NoError(t, err)
	return decodeJWTAudience(t, token)
}

// r02IssueIDAudience issues an ID token for request and returns its aud claim.
func r02IssueIDAudience(t *testing.T, store *Storage, request op.IDTokenRequest) []string {
	t.Helper()
	token, err := op.CreateIDToken(context.Background(), "http://test.example.com", request,
		time.Hour, "", "", store, &Client{id: r02client})
	require.NoError(t, err)
	return decodeJWTAudience(t, token)
}

// r02TokenExchangeRequest is a token exchange request with an effective
// resource selection, exercising the exchangeRefreshToken persist path.
type r02TokenExchangeRequest struct {
	op.TokenExchangeRequest
	grantedResources []string
	currentResources []string
}

func (r *r02TokenExchangeRequest) GetAMR() []string           { return []string{"pwd"} }
func (r *r02TokenExchangeRequest) GetAudience() []string      { return []string{r02client} }
func (r *r02TokenExchangeRequest) GetAuthTime() time.Time     { return time.Now() }
func (r *r02TokenExchangeRequest) GetClientID() string        { return r02client }
func (r *r02TokenExchangeRequest) GetScopes() []string        { return []string{"openid"} }
func (r *r02TokenExchangeRequest) GetSubject() string         { return "id1" }
func (r *r02TokenExchangeRequest) GetExchangeActor() string   { return "" }
func (r *r02TokenExchangeRequest) GetExchangeSubject() string { return "id1" }
func (r *r02TokenExchangeRequest) GetResource() []string      { return r.grantedResources }
func (r *r02TokenExchangeRequest) GetCurrentResources() []string {
	return r.currentResources
}
func (r *r02TokenExchangeRequest) SetCurrentResources(resources []string) {
	r.currentResources = resources
}
func (r *r02TokenExchangeRequest) GetAccessTokenAudience() []string {
	effective := r.grantedResources
	if r.currentResources != nil {
		effective = r.currentResources
	}
	return audienceFromResources(r02client, effective)
}

// TestR02StoredAudienceMatchesJWTAudience shows that every issuance path
// persists the effective access audience ([web-app, A]) JWTs carry for the
// same request, while ID tokens stay addressed to the client alone.
func TestR02StoredAudienceMatchesJWTAudience(t *testing.T) {
	ctx := context.Background()

	t.Run("CreateAccessToken persists the effective audience", func(t *testing.T) {
		store := r02Store()
		authReq := authRequestToInternal(&oidc.AuthRequest{
			ClientID: r02client,
			Scopes:   []string{"openid"},
			Resource: []string{r02resA},
		}, "id1")
		require.NoError(t, op.ValidateTokenRequestResources([]string{r02resA}, authReq))

		assert.Equal(t, []string{r02client, r02resA}, r02IssueJWT(t, store, authReq),
			"JWT aud is the effective audience")

		accessTokenID, _, err := store.CreateAccessToken(ctx, authReq)
		require.NoError(t, err)
		stored, ok := store.tokens[accessTokenID]
		require.True(t, ok, "access token must be stored")
		assert.Equal(t, []string{r02client, r02resA}, stored.Audience,
			"opaque record must carry the JWT audience, not the ID audience")

		assert.Equal(t, []string{r02client}, r02IssueIDAudience(t, store, authReq),
			"ID token stays addressed to the client alone")
	})

	t.Run("CreateAccessAndRefreshTokens persists the effective audience", func(t *testing.T) {
		store := r02Store()
		authReq := authRequestToInternal(&oidc.AuthRequest{
			ClientID: r02client,
			Scopes:   []string{"openid"},
			Resource: []string{r02resA, r02resB},
		}, "id1")
		require.NoError(t, op.ValidateTokenRequestResources([]string{r02resA}, authReq))

		accessTokenID, refreshToken, _, err := store.CreateAccessAndRefreshTokens(ctx, authReq, "")
		require.NoError(t, err)
		stored, ok := store.tokens[accessTokenID]
		require.True(t, ok, "access token must be stored")
		assert.Equal(t, []string{r02client, r02resA}, r02IssueJWT(t, store, authReq))
		assert.Equal(t, []string{r02client, r02resA}, stored.Audience,
			"opaque record must carry the narrowed JWT audience")

		// rotation to the other granted resource re-binds both audiences
		refreshReq, err := store.TokenRequestByRefreshToken(ctx, refreshToken)
		require.NoError(t, err)
		require.NoError(t, op.ValidateTokenRequestResources([]string{r02resB}, refreshReq))
		rotated, ok := refreshReq.(op.TokenRequest)
		require.True(t, ok)
		rotatedID, _, _, err := store.CreateAccessAndRefreshTokens(ctx, rotated, refreshToken)
		require.NoError(t, err)
		assert.Equal(t, []string{r02client, r02resB}, r02IssueJWT(t, store, rotated))
		assert.Equal(t, []string{r02client, r02resB}, store.tokens[rotatedID].Audience,
			"rotated opaque record must carry the narrowed JWT audience")
	})

	t.Run("exchangeRefreshToken persists the effective audience", func(t *testing.T) {
		store := r02Store()
		request := &r02TokenExchangeRequest{grantedResources: []string{r02resA, r02resB}}
		require.NoError(t, op.ValidateTokenRequestResources([]string{r02resA}, request))

		assert.Equal(t, []string{r02client, r02resA}, r02IssueJWT(t, store, request),
			"JWT aud is the effective audience")

		accessTokenID, _, _, err := store.exchangeRefreshToken(ctx, request)
		require.NoError(t, err)
		stored, ok := store.tokens[accessTokenID]
		require.True(t, ok, "access token must be stored")
		assert.Equal(t, []string{r02client, r02resA}, stored.Audience,
			"opaque record must carry the JWT audience, not the ID audience")
	})

	t.Run("device flow persists the effective audience", func(t *testing.T) {
		store := r02Store()
		state := &op.DeviceAuthorizationState{
			ClientID: r02client,
			Scopes:   []string{"openid"},
			Subject:  "id1",
			AuthTime: time.Now(),
			AMR:      []string{"pwd"},
			Resource: []string{r02resA, r02resB},
		}
		require.NoError(t, op.ValidateTokenRequestResources([]string{r02resA}, state))

		assert.Equal(t, []string{r02client, r02resA}, r02IssueJWT(t, store, state),
			"JWT aud is the effective audience")

		accessTokenID, _, err := store.CreateAccessToken(ctx, state)
		require.NoError(t, err)
		stored, ok := store.tokens[accessTokenID]
		require.True(t, ok, "access token must be stored")
		assert.Equal(t, []string{r02client, r02resA}, stored.Audience,
			"opaque record must carry the JWT audience, not the ID audience")

		assert.Equal(t, []string{r02client}, r02IssueIDAudience(t, store, state),
			"ID token stays addressed to the client alone")
	})

	t.Run("client_credentials persists the effective audience", func(t *testing.T) {
		store := r02ServiceStore(r02client, []string{r02resA})
		request, err := store.ClientCredentialsTokenRequest(ctx, r02client, []string{"scope"})
		require.NoError(t, err)
		require.NoError(t, op.ValidateTokenRequestResourcesStrict([]string{r02resA}, request))

		assert.Equal(t, []string{r02client, r02resA}, r02IssueJWT(t, store, request),
			"JWT aud is the effective audience")

		accessTokenID, _, err := store.CreateAccessToken(ctx, request)
		require.NoError(t, err)
		stored, ok := store.tokens[accessTokenID]
		require.True(t, ok, "access token must be stored")
		assert.Equal(t, []string{r02client, r02resA}, stored.Audience,
			"opaque record must carry the JWT audience, not the ID audience")
	})

	t.Run("resourceless flow keeps the client audience", func(t *testing.T) {
		store := r02Store()
		authReq := authRequestToInternal(&oidc.AuthRequest{
			ClientID: r02client,
			Scopes:   []string{"openid"},
		}, "id1")

		accessTokenID, _, err := store.CreateAccessToken(ctx, authReq)
		require.NoError(t, err)
		assert.Equal(t, []string{r02client}, store.tokens[accessTokenID].Audience)
		assert.Equal(t, []string{r02client}, r02IssueJWT(t, store, authReq))
	})
}

// r02Introspect calls SetIntrospectionFromToken and returns the response.
func r02Introspect(t *testing.T, store *Storage, tokenID, subject, caller string) (*oidc.IntrospectionResponse, error) {
	t.Helper()
	response := new(oidc.IntrospectionResponse)
	err := store.SetIntrospectionFromToken(context.Background(), response, tokenID, subject, caller)
	return response, err
}

// requireR02Denied asserts an introspection refusal leaks no sensitive information.
func requireR02Denied(t *testing.T, store *Storage, tokenID, caller string) {
	t.Helper()
	response, err := r02Introspect(t, store, tokenID, "id1", caller)
	require.Error(t, err, "caller %q must learn nothing (inactive at the endpoint)", caller)
	assert.Empty(t, response.Scope, "refusal must leak no scopes")
	assert.Empty(t, response.ClientID, "refusal must leak no client")
	assert.Empty(t, response.Subject, "refusal must leak no subject")
	assert.Empty(t, response.Audience, "refusal must leak no audience")
	assert.Empty(t, response.Username, "refusal must leak no userinfo")
	assert.Zero(t, response.Expiration, "refusal must leak nothing, not even expiry")
}

// TestR02IntrospectionAudienceAndMapping shows that introspection of a token
// issued for A succeeds for the mapped resource server and the issuing client
// only, and that active responses carry the effective audience. Any other
// caller learns nothing (inactive at the endpoint), as do callers of invalid
// or expired tokens.
func TestR02IntrospectionAudienceAndMapping(t *testing.T) {
	ctx := context.Background()
	store := r02Store()

	authReq := authRequestToInternal(&oidc.AuthRequest{
		ClientID: r02client,
		Scopes:   []string{"openid"},
		Resource: []string{r02resA},
	}, "id1")
	require.NoError(t, op.ValidateTokenRequestResources([]string{r02resA}, authReq))
	resourceTokenID, _, _, err := store.CreateAccessAndRefreshTokens(ctx, authReq, "")
	require.NoError(t, err)

	legacyReq := authRequestToInternal(&oidc.AuthRequest{
		ClientID: r02client,
		Scopes:   []string{"openid"},
	}, "id1")
	legacyTokenID, _, _, err := store.CreateAccessAndRefreshTokens(ctx, legacyReq, "")
	require.NoError(t, err)

	t.Run("mapped resource server learns the effective audience", func(t *testing.T) {
		response, err := r02Introspect(t, store, resourceTokenID, "id1", "rs-a")
		require.NoError(t, err)
		assert.Equal(t, oidc.Audience{r02client, r02resA}, response.Audience)
		assert.Equal(t, r02client, response.ClientID)
		assert.Equal(t, "id1", response.Subject)
	})

	t.Run("server mapped to another resource learns nothing", func(t *testing.T) {
		requireR02Denied(t, store, resourceTokenID, "rs-b")
	})

	t.Run("unknown caller learns nothing", func(t *testing.T) {
		requireR02Denied(t, store, resourceTokenID, "unknown-rs")
	})

	t.Run("issuing client keeps introspecting its token", func(t *testing.T) {
		response, err := r02Introspect(t, store, resourceTokenID, "id1", r02client)
		require.NoError(t, err)
		assert.Equal(t, oidc.Audience{r02client, r02resA}, response.Audience)
		assert.Equal(t, r02client, response.ClientID)
	})

	t.Run("resourceless token keeps the historical rule", func(t *testing.T) {
		response, err := r02Introspect(t, store, legacyTokenID, "id1", r02client)
		require.NoError(t, err)
		assert.Equal(t, oidc.Audience{r02client}, response.Audience)
		requireR02Denied(t, store, legacyTokenID, "rs-a")
	})

	t.Run("invalid token is refused", func(t *testing.T) {
		response, err := r02Introspect(t, store, "no-such-token", "id1", r02client)
		require.Error(t, err)
		assert.Empty(t, response.Subject)
		assert.Empty(t, response.Audience)
	})

	t.Run("expired token is refused", func(t *testing.T) {
		expiringReq := authRequestToInternal(&oidc.AuthRequest{
			ClientID: r02client,
			Scopes:   []string{"openid"},
			Resource: []string{r02resA},
		}, "id1")
		require.NoError(t, op.ValidateTokenRequestResources([]string{r02resA}, expiringReq))
		expiringID, _, _, err := store.CreateAccessAndRefreshTokens(ctx, expiringReq, "")
		require.NoError(t, err)
		store.tokens[expiringID].Expiration = time.Now().Add(-time.Hour)

		response, err := r02Introspect(t, store, expiringID, "id1", r02client)
		require.Error(t, err)
		assert.Empty(t, response.Subject)
		assert.Empty(t, response.Audience)
	})
}
