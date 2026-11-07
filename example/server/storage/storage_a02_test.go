package storage

// A02 reproduction: token subject provenance must be recorded at issuance,
// never inferred from user-store lookups. Two counterexamples against the
// R05 heuristic: (1) a service client whose ID collides with a human user
// must not receive that human's claims; (2) a human token whose user
// disappeared must follow the explicit deleted-user policy (introspection
// fails closed) instead of being reclassified as a machine.

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

const (
	a02human = "id1" // the example human in NewUserStore
	a02resA  = "https://a.example.com"
	a02rsA   = "rs-a"
)

// a02Store holds a web client, a resource server mapped to A, and a
// colliding service client sharing the human's ID.
func a02Store() *Storage {
	store := NewStorageWithClients(
		NewUserStore("http://test.example.com"),
		map[string]*Client{
			"web-app": WebClient("web-app", "secret"),
			a02rsA:    {id: a02rsA, secret: "secret", introspectionResources: []string{a02resA}},
		},
	)
	store.serviceUsers[a02human] = &Client{
		id:               a02human,
		secret:           "verysecret",
		grantTypes:       []oidc.GrantType{oidc.GrantTypeClientCredentials},
		accessTokenType:  op.AccessTokenTypeBearer,
		allowedResources: []string{a02resA},
	}
	return store
}

// a02MachineTokenID issues a client_credentials token for the colliding
// service client, narrowed to A, and returns its internal token ID.
func a02MachineTokenID(t *testing.T, store *Storage) string {
	t.Helper()
	ctx := context.Background()
	req, err := store.ClientCredentialsTokenRequest(ctx, a02human, []string{"openid", "profile", "email"})
	require.NoError(t, err)
	require.NoError(t, op.ValidateTokenRequestResources([]string{a02resA}, req))
	tokenID, _, err := store.CreateAccessToken(ctx, req)
	require.NoError(t, err)
	return tokenID
}

// a02HumanTokenID issues an authorization-code token for the human, narrowed
// to A, and returns its internal token ID.
func a02HumanTokenID(t *testing.T, store *Storage) string {
	t.Helper()
	authReq := authRequestToInternal(&oidc.AuthRequest{
		ClientID: "web-app",
		Scopes:   []string{"openid", "profile", "email"},
		Resource: []string{a02resA},
	}, a02human)
	require.NoError(t, op.ValidateTokenRequestResources([]string{a02resA}, authReq))
	tokenID, _, _, err := store.CreateAccessAndRefreshTokens(context.Background(), authReq, "")
	require.NoError(t, err)
	return tokenID
}

func TestA02SubjectCollision(t *testing.T) {
	ctx := context.Background()

	t.Run("machine token with colliding ID gets no human claims (storage)", func(t *testing.T) {
		store := a02Store()
		tokenID := a02MachineTokenID(t, store)

		response := new(oidc.IntrospectionResponse)
		require.NoError(t, store.SetIntrospectionFromToken(ctx, response, tokenID, a02human, a02rsA))
		assert.Equal(t, a02human, response.Subject)
		assert.Equal(t, a02human, response.ClientID)
		assert.Empty(t, response.Email, "machine token must not carry the human's email")
		assert.Empty(t, response.PreferredUsername, "machine token must not carry the human's username")
		assert.Empty(t, response.Name, "machine token must not carry the human's name")
	})

	t.Run("machine token with colliding ID gets no human claims (HTTP)", func(t *testing.T) {
		paths := map[string]func(*testing.T, op.OpenIDProvider, string, string) (int, string){
			"legacy": doR04IntrospectLegacy,
			"server": doR04IntrospectServer,
		}
		for name, do := range paths {
			store := a02Store()
			provider := devHTTPProvider(t, store, true)
			req, err := store.ClientCredentialsTokenRequest(ctx, a02human, []string{"openid", "profile", "email"})
			require.NoError(t, err, "path %s", name)
			require.NoError(t, op.ValidateTokenRequestResources([]string{a02resA}, req), "path %s", name)
			bearer, _, _, err := op.CreateAccessToken(ctx, req,
				op.AccessTokenTypeBearer, provider, store.serviceUsers[a02human], "")
			require.NoError(t, err, "path %s", name)

			status, body := do(t, provider, bearer, a02rsA)
			assert.Equal(t, http.StatusOK, status, "path %s", name)
			assert.Contains(t, body, `"active":true`, "path %s: %s", name, body)
			assert.NotContains(t, body, "test-user@zitadel.ch", "path %s: no human email leak: %s", name, body)
			assert.NotContains(t, body, "Test User", "path %s: no human name leak: %s", name, body)
		}
	})

	t.Run("human token keeps its user claims (no regression)", func(t *testing.T) {
		store := a02Store()
		tokenID := a02HumanTokenID(t, store)

		response := new(oidc.IntrospectionResponse)
		require.NoError(t, store.SetIntrospectionFromToken(ctx, response, tokenID, a02human, a02rsA))
		assert.Equal(t, "test-user@zitadel.ch", response.Email)
		assert.NotEmpty(t, response.PreferredUsername)
	})
}

func TestA02DeletedHuman(t *testing.T) {
	// Explicit deleted-user policy for the example storage: introspection of
	// a recorded-human token whose user no longer exists fails closed
	// (inactive). This is NOT a general revocation rule: the token record
	// still exists, and refresh behavior is unchanged.
	t.Run("human token with deleted user is inactive, never a machine", func(t *testing.T) {
		store := a02Store()
		tokenID := a02HumanTokenID(t, store)

		before := new(oidc.IntrospectionResponse)
		require.NoError(t, store.SetIntrospectionFromToken(context.Background(), before, tokenID, a02human, a02rsA))

		users := store.userStore.(userStore).users
		require.Contains(t, users, a02human)
		delete(users, a02human)

		after := new(oidc.IntrospectionResponse)
		err := store.SetIntrospectionFromToken(context.Background(), after, tokenID, a02human, a02rsA)
		require.Error(t, err, "deleted human must fail closed (inactive at the endpoint)")
		assert.Empty(t, after.Subject, "refusal must leak nothing, not even a machine-style subject")
		assert.Empty(t, after.Audience)
	})

	t.Run("token record still exists (no silent revocation)", func(t *testing.T) {
		store := a02Store()
		tokenID := a02HumanTokenID(t, store)
		delete(store.userStore.(userStore).users, a02human)

		_, stillThere := store.tokens[tokenID]
		assert.True(t, stillThere, "failing closed is not revocation")
	})
}

func TestA02KindPreservedThroughRefresh(t *testing.T) {
	ctx := context.Background()

	t.Run("refreshed human token keeps user claims", func(t *testing.T) {
		store := a02Store()
		authReq := authRequestToInternal(&oidc.AuthRequest{
			ClientID: "web-app",
			Scopes:   []string{"openid", "profile", "email", "offline_access"},
		}, a02human)
		_, refreshToken, _, err := store.CreateAccessAndRefreshTokens(ctx, authReq, "")
		require.NoError(t, err)

		refreshReq, err := store.TokenRequestByRefreshToken(ctx, refreshToken)
		require.NoError(t, err)
		accessID, _, _, err := store.CreateAccessAndRefreshTokens(ctx, refreshReq, refreshToken)
		require.NoError(t, err)

		response := new(oidc.IntrospectionResponse)
		require.NoError(t, store.SetIntrospectionFromToken(ctx, response, accessID, a02human, "web-app"))
		assert.Equal(t, "test-user@zitadel.ch", response.Email, "refresh must preserve the human kind")
	})

	t.Run("refreshed machine token stays a machine", func(t *testing.T) {
		store := a02Store()
		scopes := []string{"openid", "profile", "email", "offline_access"}
		req, err := store.ClientCredentialsTokenRequest(ctx, a02human, scopes)
		require.NoError(t, err)
		require.NoError(t, op.ValidateTokenRequestResources([]string{a02resA}, req))
		_, refreshToken, _, err := store.CreateAccessAndRefreshTokens(ctx, req, "")
		require.NoError(t, err)

		refreshReq, err := store.TokenRequestByRefreshToken(ctx, refreshToken)
		require.NoError(t, err)
		require.NoError(t, op.ValidateRefreshTokenScopes(scopes, refreshReq))
		accessID, _, _, err := store.CreateAccessAndRefreshTokens(ctx, refreshReq, refreshToken)
		require.NoError(t, err)

		response := new(oidc.IntrospectionResponse)
		require.NoError(t, store.SetIntrospectionFromToken(ctx, response, accessID, a02human, a02rsA))
		assert.Equal(t, a02human, response.Subject)
		assert.Empty(t, response.Email, "refreshed machine token must not gain human claims")
	})

	t.Run("invalid token stays refused", func(t *testing.T) {
		store := a02Store()
		response := new(oidc.IntrospectionResponse)
		require.Error(t, store.SetIntrospectionFromToken(ctx, response, "no-such-token", a02human, a02rsA))
		assert.Empty(t, response.Subject)
	})
}
