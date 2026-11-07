package storage

// R04 reproduction: an OAuth resource grant must not confer introspection
// authority. A regular OAuth client whose grant policy (allowedResources)
// covers resource A must NOT learn about another client's token issued for A;
// only the issuing client and explicitly mapped resource servers may
// introspect it. The R02 suite only used resource-server fixtures and never
// exercised a different OAuth client holding the same grant allowlist.

import (
	"context"
	"io"
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
	r04appA = "app-a"
	r04appB = "app-b"
	r04resA = "https://a.example.com"
	r04rsA  = "rs-a"
)

// r04Store holds two regular OAuth clients sharing the same grant policy for
// resource A, plus the resource server mapped to A.
func r04Store() *Storage {
	appA := WebClient(r04appA, "secret")
	appA.allowedResources = []string{r04resA}
	appB := WebClient(r04appB, "secret")
	appB.allowedResources = []string{r04resA}
	rsA := &Client{id: r04rsA, secret: "secret", introspectionResources: []string{r04resA}}
	return NewStorageWithClients(
		NewUserStore("http://test.example.com"),
		map[string]*Client{r04appA: appA, r04appB: appB, r04rsA: rsA},
	)
}

// r04IssueTokenID issues an opaque access token for appB narrowed to A and
// returns its internal token ID.
func r04IssueTokenID(t *testing.T, store *Storage) string {
	t.Helper()
	authReq := authRequestToInternal(&oidc.AuthRequest{
		ClientID: r04appB,
		Scopes:   []string{"openid"},
		Resource: []string{r04resA},
	}, "id1")
	require.NoError(t, op.ValidateTokenRequestResources([]string{r04resA}, authReq))
	tokenID, _, _, err := store.CreateAccessAndRefreshTokens(context.Background(), authReq, "")
	require.NoError(t, err)
	return tokenID
}

// r04Bearer issues a real opaque bearer access token string for appB/A.
func r04Bearer(t *testing.T, provider op.OpenIDProvider, store *Storage) string {
	t.Helper()
	authReq := authRequestToInternal(&oidc.AuthRequest{
		ClientID: r04appB,
		Scopes:   []string{"openid"},
		Resource: []string{r04resA},
	}, "id1")
	require.NoError(t, op.ValidateTokenRequestResources([]string{r04resA}, authReq))
	bearer, _, _, err := op.CreateAccessToken(context.Background(), authReq,
		op.AccessTokenTypeBearer, provider, store.clients[r04appB], "")
	require.NoError(t, err)
	require.NotEmpty(t, bearer)
	return bearer
}

func r04IntrospectRequest(t *testing.T, path, bearer, basicUser, basicPass string) *http.Request {
	t.Helper()
	values := url.Values{"token": {bearer}}
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(basicUser, basicPass)
	return r.WithContext(op.ContextWithIssuer(r.Context(), devHTTPIssuer))
}

func r04ReadBody(t *testing.T, w *httptest.ResponseRecorder) (int, string) {
	t.Helper()
	result := w.Result()
	body, err := io.ReadAll(result.Body)
	require.NoError(t, err)
	return result.StatusCode, string(body)
}

// doR04IntrospectLegacy introspects over HTTP through the legacy handler.
func doR04IntrospectLegacy(t *testing.T, provider op.OpenIDProvider, bearer, basicUser string) (int, string) {
	t.Helper()
	w := httptest.NewRecorder()
	op.Introspect(w, r04IntrospectRequest(t, "/", bearer, basicUser, "secret"), provider)
	return r04ReadBody(t, w)
}

// doR04IntrospectServer introspects over HTTP through the new Server routes.
func doR04IntrospectServer(t *testing.T, provider op.OpenIDProvider, bearer, basicUser string) (int, string) {
	t.Helper()
	server := op.RegisterLegacyServer(
		op.NewLegacyServer(provider, *op.DefaultEndpoints),
		op.AuthorizeCallbackHandler(provider),
	)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, r04IntrospectRequest(t,
		provider.IntrospectionEndpoint().Relative(), bearer, basicUser, "secret"))
	return r04ReadBody(t, w)
}

func TestR04GrantIsNotIntrospectionAuthority(t *testing.T) {
	t.Run("another OAuth client with the same grant policy learns nothing (storage)", func(t *testing.T) {
		store := r04Store()
		tokenID := r04IssueTokenID(t, store)
		requireR02Denied(t, store, tokenID, r04appA)
	})

	t.Run("mapped resource server keeps access (storage)", func(t *testing.T) {
		store := r04Store()
		tokenID := r04IssueTokenID(t, store)
		response, err := r02Introspect(t, store, tokenID, "id1", r04rsA)
		require.NoError(t, err)
		assert.Equal(t, oidc.Audience{r04appB, r04resA}, response.Audience)
		assert.Equal(t, r04appB, response.ClientID)
	})

	t.Run("issuing client keeps access (storage)", func(t *testing.T) {
		store := r04Store()
		tokenID := r04IssueTokenID(t, store)
		response, err := r02Introspect(t, store, tokenID, "id1", r04appB)
		require.NoError(t, err)
		assert.Equal(t, oidc.Audience{r04appB, r04resA}, response.Audience)
	})

	paths := map[string]func(*testing.T, op.OpenIDProvider, string, string) (int, string){
		"legacy": doR04IntrospectLegacy,
		"server": doR04IntrospectServer,
	}

	t.Run("another OAuth client with the same grant policy is inactive (HTTP)", func(t *testing.T) {
		for name, do := range paths {
			store := r04Store()
			provider := devHTTPProvider(t, store, true)
			bearer := r04Bearer(t, provider, store)

			status, body := do(t, provider, bearer, r04appA)
			assert.Equal(t, http.StatusOK, status, "path %s", name)
			assert.Contains(t, body, `"active":false`, "path %s: %s", name, body)
			assert.NotContains(t, body, r04resA, "path %s: refusal must leak no audience", name)
		}
	})

	t.Run("mapped resource server is active (HTTP)", func(t *testing.T) {
		for name, do := range paths {
			store := r04Store()
			provider := devHTTPProvider(t, store, true)
			bearer := r04Bearer(t, provider, store)

			status, body := do(t, provider, bearer, r04rsA)
			assert.Equal(t, http.StatusOK, status, "path %s", name)
			assert.Contains(t, body, `"active":true`, "path %s: %s", name, body)
			assert.Contains(t, body, r04resA, "path %s: mapped RS learns the audience", name)
		}
	})
}
