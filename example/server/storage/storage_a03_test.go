package storage

// A03 characterization: machine-token revocation works at the storage layer
// (R05, A02), but end-to-end HTTP revocation by a service-only client fails
// at client authentication. Service clients live in the serviceUsers
// registry while AuthorizeClientIDSecret/GetClientByClientID consult only
// clients, and the new server selects service credentials only when the form
// carries grant_type=client_credentials, which RFC 7009 requests do not.
// That split predates this contribution (identical at 5905998) and is pinned
// here as an inherited limitation, not a newly introduced defect.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

const (
	a03resA = "https://a.example.com"
	a03rsA  = "rs-a"
	a03svc  = "svc-a"
)

// a03Store holds a regular web client, a service client with the same grant
// policy, and the resource server mapped to A.
func a03Store() *Storage {
	web := WebClient("web-app", "secret")
	web.allowedResources = []string{a03resA}
	store := NewStorageWithClients(
		NewUserStore("http://test.example.com"),
		map[string]*Client{
			"web-app": web,
			"app-b":   WebClient("app-b", "secret"),
			a03rsA:    {id: a03rsA, secret: "secret", introspectionResources: []string{a03resA}},
		},
	)
	store.serviceUsers[a03svc] = &Client{
		id:               a03svc,
		secret:           "verysecret",
		grantTypes:       []oidc.GrantType{oidc.GrantTypeClientCredentials},
		accessTokenType:  op.AccessTokenTypeBearer,
		allowedResources: []string{a03resA},
	}
	return store
}

func a03RevokeRequest(t *testing.T, path, bearer, basicUser, basicPass string) *http.Request {
	t.Helper()
	// Plain RFC 7009 form: no grant_type injection.
	values := url.Values{"token": {bearer}}
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(basicUser, basicPass)
	return r.WithContext(op.ContextWithIssuer(r.Context(), devHTTPIssuer))
}

// doA03RevokeLegacy revokes over HTTP through the legacy handler.
func doA03RevokeLegacy(t *testing.T, provider op.OpenIDProvider, bearer, basicUser, basicPass string) (int, string) {
	t.Helper()
	w := httptest.NewRecorder()
	op.Revoke(w, a03RevokeRequest(t, "/", bearer, basicUser, basicPass), provider)
	return r04ReadBody(t, w)
}

// doA03RevokeServer revokes over HTTP through the new Server routes.
func doA03RevokeServer(t *testing.T, provider op.OpenIDProvider, bearer, basicUser, basicPass string) (int, string) {
	t.Helper()
	server := op.RegisterLegacyServer(
		op.NewLegacyServer(provider, *op.DefaultEndpoints),
		op.AuthorizeCallbackHandler(provider),
	)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, a03RevokeRequest(t,
		provider.RevocationEndpoint().Relative(), bearer, basicUser, basicPass))
	return r04ReadBody(t, w)
}

// a03WebBearer issues a real opaque bearer token for web-app/A.
func a03WebBearer(t *testing.T, provider op.OpenIDProvider, store *Storage) string {
	t.Helper()
	authReq := authRequestToInternal(&oidc.AuthRequest{
		ClientID: "web-app",
		Scopes:   []string{"openid"},
		Resource: []string{a03resA},
	}, "id1")
	require.NoError(t, op.ValidateTokenRequestResources([]string{a03resA}, authReq))
	bearer, _, _, err := op.CreateAccessToken(context.Background(), authReq,
		op.AccessTokenTypeBearer, provider, store.clients["web-app"], "")
	require.NoError(t, err)
	return bearer
}

// a03ServiceBearer issues a real opaque bearer token for the service client.
func a03ServiceBearer(t *testing.T, provider op.OpenIDProvider, store *Storage) string {
	t.Helper()
	ctx := context.Background()
	req, err := store.ClientCredentialsTokenRequest(ctx, a03svc, []string{"openid"})
	require.NoError(t, err)
	require.NoError(t, op.ValidateTokenRequestResources([]string{a03resA}, req))
	bearer, _, _, err := op.CreateAccessToken(ctx, req,
		op.AccessTokenTypeBearer, provider, store.serviceUsers[a03svc], "")
	require.NoError(t, err)
	return bearer
}

func TestA03HTTPRevocationLifecycle(t *testing.T) {
	revokePaths := map[string]func(*testing.T, op.OpenIDProvider, string, string, string) (int, string){
		"legacy": doA03RevokeLegacy,
		"server": doA03RevokeServer,
	}
	introspectPaths := map[string]func(*testing.T, op.OpenIDProvider, string, string) (int, string){
		"legacy": doR04IntrospectLegacy,
		"server": doR04IntrospectServer,
	}

	t.Run("regular client full lifecycle over HTTP", func(t *testing.T) {
		for name, revoke := range revokePaths {
			store := a03Store()
			provider := devHTTPProvider(t, store, true)
			bearer := a03WebBearer(t, provider, store)
			introspect := introspectPaths[name]

			_, body := introspect(t, provider, bearer, a03rsA)
			assert.Contains(t, body, `"active":true`, "path %s: RS introspects before revocation", name)

			status, _ := revoke(t, provider, bearer, "web-app", "secret")
			assert.Equal(t, http.StatusOK, status, "path %s: owner revokes its token", name)

			_, body = introspect(t, provider, bearer, a03rsA)
			assert.Contains(t, body, `"active":false`, "path %s: token inactive after revocation", name)
		}
	})

	t.Run("service-only client revocation fails at HTTP authentication (inherited)", func(t *testing.T) {
		// Both paths refuse with invalid_client before reaching storage; the
		// legacy handler maps it to 401 while the new server answers 400
		// (WriteError has no invalid_client mapping — pre-existing framework
		// behavior, untouched here).
		wantStatus := map[string]int{
			"legacy": http.StatusUnauthorized,
			"server": http.StatusBadRequest,
		}
		for name, revoke := range revokePaths {
			store := a03Store()
			provider := devHTTPProvider(t, store, true)
			bearer := a03ServiceBearer(t, provider, store)
			introspect := introspectPaths[name]

			_, body := introspect(t, provider, bearer, a03rsA)
			assert.Contains(t, body, `"active":true`, "path %s: RS introspects before revocation", name)

			status, body := revoke(t, provider, bearer, a03svc, "verysecret")
			assert.Equal(t, wantStatus[name], status,
				"path %s: service-only client unknown to the clients registry: %s", name, body)
			assert.Contains(t, body, string(oidc.InvalidClient), "path %s", name)

			_, body = introspect(t, provider, bearer, a03rsA)
			assert.Contains(t, body, `"active":true`,
				"path %s: refused revocation leaves the token active", name)
		}
	})

	t.Run("another client cannot revoke the token", func(t *testing.T) {
		for name, revoke := range revokePaths {
			store := a03Store()
			provider := devHTTPProvider(t, store, true)
			bearer := a03WebBearer(t, provider, store)
			introspect := introspectPaths[name]

			status, _ := revoke(t, provider, bearer, "app-b", "secret")
			assert.Equal(t, http.StatusUnauthorized, status,
				"path %s: revocation by a non-owner is refused", name)

			_, body := introspect(t, provider, bearer, a03rsA)
			assert.Contains(t, body, `"active":true`,
				"path %s: refused revocation leaves the token active", name)
		}
	})

	t.Run("legacy policy-less service token keeps issuer metadata (storage)", func(t *testing.T) {
		store := a03Store()
		store.serviceUsers[a03svc].allowedResources = nil

		req, err := store.ClientCredentialsTokenRequest(context.Background(), a03svc, []string{"openid"})
		require.NoError(t, err)
		tokenID, _, err := store.CreateAccessToken(context.Background(), req)
		require.NoError(t, err)

		token := store.tokens[tokenID]
		require.NotNil(t, token)
		assert.Equal(t, a03svc, token.ApplicationID)
		assert.Equal(t, SubjectMachine, token.SubjectKind)

		response := new(oidc.IntrospectionResponse)
		require.NoError(t, store.SetIntrospectionFromToken(context.Background(), response, tokenID, a03svc, a03svc))
		assert.Equal(t, a03svc, response.ClientID)
		assert.Equal(t, a03svc, response.Subject)
	})
}
