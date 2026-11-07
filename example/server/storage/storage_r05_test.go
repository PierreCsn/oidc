package storage

// R05 reproduction: client_credentials and device opaque tokens must carry
// usable metadata and remain introspectable by a mapped resource server.
// Concretely: the persisted record must keep the issuing client
// (ApplicationID), introspection must report client_id/sub/audience as active,
// and revocation by the issuing client must work. Machine subjects have no
// human user record: introspection must report the subject without user claims
// instead of answering inactive.

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

const (
	r05svc  = "svc-a"
	r05resA = "https://a.example.com"
	r05rsA  = "rs-a"
)

// r05Store holds a client_credentials service user with the given policy and
// the resource server mapped to A.
func r05Store(policy []string) *Storage {
	store := NewStorageWithClients(
		NewUserStore("http://test.example.com"),
		map[string]*Client{
			r05rsA: {id: r05rsA, secret: "secret", allowedResources: []string{r05resA}},
		},
	)
	store.serviceUsers[r05svc] = &Client{
		id:               r05svc,
		secret:           "verysecret",
		grantTypes:       []oidc.GrantType{oidc.GrantTypeClientCredentials},
		accessTokenType:  op.AccessTokenTypeBearer,
		allowedResources: policy,
	}
	return store
}

// r05CCRequest builds a client_credentials token request narrowed to A.
func r05CCRequest(t *testing.T, store *Storage) op.TokenRequest {
	t.Helper()
	req, err := store.ClientCredentialsTokenRequest(context.Background(), r05svc, []string{"openid"})
	require.NoError(t, err)
	require.NoError(t, op.ValidateTokenRequestResources([]string{r05resA}, req))
	return req
}

// r05DeviceStore holds a device client with the given policy and rs-a.
func r05DeviceStore(policy []string) *Storage {
	device := DeviceClient("device", "secret")
	device.allowedResources = policy
	return NewStorageWithClients(
		NewUserStore("http://test.example.com"),
		map[string]*Client{
			"device": device,
			r05rsA:   {id: r05rsA, secret: "secret", allowedResources: []string{r05resA}},
		},
	)
}

// r05OnlyToken returns the single persisted access token of a fresh store.
func r05OnlyToken(t *testing.T, store *Storage) *Token {
	t.Helper()
	require.Len(t, store.tokens, 1, "fresh store must hold exactly one access token")
	for _, token := range store.tokens {
		return token
	}
	return nil
}

func TestR05ClientCredentialsOpaqueToken(t *testing.T) {
	ctx := context.Background()

	t.Run("record keeps the issuing client, audience and grant", func(t *testing.T) {
		store := r05Store([]string{r05resA})
		tokenID, _, err := store.CreateAccessToken(ctx, r05CCRequest(t, store))
		require.NoError(t, err)

		token := store.tokens[tokenID]
		require.NotNil(t, token)
		assert.Equal(t, r05svc, token.ApplicationID, "introspection client_id and revocation need the issuer")
		assert.Equal(t, []string{r05svc, r05resA}, token.Audience)
		assert.Equal(t, []string{r05resA}, token.Resource)
		assert.Equal(t, r05svc, token.Subject)
	})

	t.Run("mapped resource server introspects the service token (storage)", func(t *testing.T) {
		store := r05Store([]string{r05resA})
		tokenID, _, err := store.CreateAccessToken(ctx, r05CCRequest(t, store))
		require.NoError(t, err)

		response := new(oidc.IntrospectionResponse)
		require.NoError(t, store.SetIntrospectionFromToken(ctx, response, tokenID, r05svc, r05rsA),
			"a valid service token must stay introspectable without a human user record")
		assert.Equal(t, r05svc, response.ClientID)
		assert.Equal(t, r05svc, response.Subject)
		assert.Equal(t, oidc.Audience{r05svc, r05resA}, response.Audience)
		assert.NotZero(t, response.Expiration)
	})

	t.Run("mapped resource server introspects the service token (HTTP)", func(t *testing.T) {
		paths := map[string]func(*testing.T, op.OpenIDProvider, string, string) (int, string){
			"legacy": doR04IntrospectLegacy,
			"server": doR04IntrospectServer,
		}
		for name, do := range paths {
			store := r05Store([]string{r05resA})
			provider := devHTTPProvider(t, store, true)
			bearer, _, _, err := op.CreateAccessToken(ctx, r05CCRequest(t, store),
				op.AccessTokenTypeBearer, provider, store.serviceUsers[r05svc], "")
			require.NoError(t, err, "path %s", name)

			status, body := do(t, provider, bearer, r05rsA)
			assert.Equal(t, http.StatusOK, status, "path %s", name)
			assert.Contains(t, body, `"active":true`, "path %s: %s", name, body)
			assert.Contains(t, body, `"client_id":"`+r05svc+`"`, "path %s: %s", name, body)
			assert.Contains(t, body, r05resA, "path %s: RS learns the audience", name)
		}
	})

	t.Run("issuing service client can revoke its token", func(t *testing.T) {
		store := r05Store([]string{r05resA})
		tokenID, _, err := store.CreateAccessToken(ctx, r05CCRequest(t, store))
		require.NoError(t, err)

		assert.Nil(t, store.RevokeToken(ctx, tokenID, r05svc, r05svc),
			"revocation checks ApplicationID against the calling client")
		_, stillThere := store.tokens[tokenID]
		assert.False(t, stillThere, "token must be gone after revocation")
	})
}

func TestR05DeviceOpaqueToken(t *testing.T) {
	ctx := context.Background()

	// r05IssueDevice completes a device flow for A and returns the bearer token.
	r05IssueDevice := func(t *testing.T, store *Storage, provider op.OpenIDProvider) string {
		t.Helper()
		expires := time.Now().Add(5 * time.Minute)
		require.NoError(t, store.StoreDeviceAuthorizationWithResources(ctx,
			"device", "dev-code-1", "user-code-1", expires, []string{"openid"}, []string{r05resA}))
		require.NoError(t, store.CompleteDeviceAuthorization(ctx, "user-code-1", "id1"))

		state, err := op.CheckDeviceAuthorizationState(ctx, "device", "dev-code-1", provider)
		require.NoError(t, err)
		require.NoError(t, op.ValidateTokenRequestResources([]string{r05resA}, state))

		resp, err := op.CreateDeviceTokenResponse(ctx, state, provider, store.clients["device"])
		require.NoError(t, err)
		require.NotEmpty(t, resp.AccessToken)
		return resp.AccessToken
	}

	t.Run("record keeps the issuing client, audience and grant", func(t *testing.T) {
		store := r05DeviceStore([]string{r05resA})
		provider := devHTTPProvider(t, store, true)
		r05IssueDevice(t, store, provider)

		token := r05OnlyToken(t, store)
		assert.Equal(t, "device", token.ApplicationID)
		assert.Equal(t, []string{"device", r05resA}, token.Audience)
		assert.Equal(t, []string{r05resA}, token.Resource)
		assert.Equal(t, "id1", token.Subject)
	})

	t.Run("mapped resource server introspects the device token", func(t *testing.T) {
		paths := map[string]func(*testing.T, op.OpenIDProvider, string, string) (int, string){
			"legacy": doR04IntrospectLegacy,
			"server": doR04IntrospectServer,
		}
		for name, do := range paths {
			store := r05DeviceStore([]string{r05resA})
			provider := devHTTPProvider(t, store, true)
			bearer := r05IssueDevice(t, store, provider)

			status, body := do(t, provider, bearer, r05rsA)
			assert.Equal(t, http.StatusOK, status, "path %s", name)
			assert.Contains(t, body, `"active":true`, "path %s: %s", name, body)
			assert.Contains(t, body, `"client_id":"device"`, "path %s: %s", name, body)
			assert.Contains(t, body, `"sub":"id1"`, "path %s: %s", name, body)
		}
	})
}

func TestR05AuthCodeBaseline(t *testing.T) {
	// The authorization-code path is the reference R02 already covers; this
	// baseline locks the same four introspection fields here so the R05 matrix
	// (CC, device, code) is readable in one place.
	store := r04Store()
	tokenID := r04IssueTokenID(t, store)

	response, err := r02Introspect(t, store, tokenID, "id1", r04rsA)
	require.NoError(t, err)
	assert.Equal(t, r04appB, response.ClientID)
	assert.Equal(t, "id1", response.Subject)
	assert.Equal(t, oidc.Audience{r04appB, r04resA}, response.Audience)
	assert.NotZero(t, response.Expiration)
}
