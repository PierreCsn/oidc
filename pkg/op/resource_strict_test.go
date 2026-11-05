package op_test

// Full-path strict resource enforcement tests.
//
// These tests drive the legacy HTTP server and the package-level device
// handlers with providers that advertise RFC 8707 support. The new HTTP
// server delegates its token endpoints to the same LegacyServer methods
// (see server_http.go), so these paths cover both servers.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/muhlemmer/gu"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/example/server/storage"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// newStrictTestProvider returns an OpenIDProvider with fresh example storage
// that advertises RFC 8707 support.
func newStrictTestProvider(t *testing.T) op.OpenIDProvider {
	t.Helper()
	conf := gu.PtrCopy(testConfig)
	conf.ResourceIndicatorsSupported = true
	return newTestProvider(conf)
}

// deviceStorageWithoutResources hides the optional resource-aware device
// storage interface from a wrapped Storage.
type deviceStorageWithoutResources struct {
	op.Storage
	op.DeviceAuthorizationStorage
}

func providerWithStorage(t *testing.T, advertise bool, store op.Storage) op.OpenIDProvider {
	t.Helper()
	conf := gu.PtrCopy(testConfig)
	conf.ResourceIndicatorsSupported = advertise
	keySet := &op.OpenIDKeySet{Storage: store}
	provider, err := op.NewOpenIDProvider(testIssuer, conf, store,
		op.WithAllowInsecure(),
		op.WithAccessTokenKeySet(keySet),
		op.WithIDTokenHintKeySet(keySet),
	)
	require.NoError(t, err)
	return provider
}

func postToken(t *testing.T, server http.Handler, form url.Values, clientID, secret string) (int, []byte) {
	t.Helper()
	u, err := url.Parse(testProvider.TokenEndpoint().Absolute(testIssuer))
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, u.String(), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(secret))
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	resp := rec.Result()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, body
}

func requireInvalidTargetResponse(t *testing.T, status int, body []byte) {
	t.Helper()
	require.Equal(t, http.StatusBadRequest, status, "body: %s", body)
	var errResp oidc.Error
	require.NoError(t, json.Unmarshal(body, &errResp))
	require.Equal(t, oidc.InvalidTarget, errResp.ErrorType, "body: %s", body)
}

// TestStrictCodeRefreshFlow drives the authorization_code grant followed by
// refreshes on a provider that advertises RFC 8707: narrowing to a granted
// subset succeeds, the refresh token keeps the full grant across narrowing,
// and anything outside the grant fails with invalid_target.
func TestStrictCodeRefreshFlow(t *testing.T) {
	const (
		mcp   = "https://mcp.example.com/mcp"
		api   = "https://api.example.com"
		other = "https://other.example.com"
	)
	provider := newStrictTestProvider(t)
	server := op.RegisterLegacyServer(
		op.NewLegacyServer(provider, *op.DefaultEndpoints),
		op.AuthorizeCallbackHandler(provider),
	)
	store := provider.Storage().(routesTestStorage)
	ctx := op.ContextWithIssuer(context.Background(), testIssuer)

	newCode := func(t *testing.T, code string) {
		t.Helper()
		authReq, err := store.CreateAuthRequest(ctx, &oidc.AuthRequest{
			ClientID:     "web",
			RedirectURI:  "https://example.com",
			Scopes:       oidc.SpaceDelimitedArray{oidc.ScopeOpenID, oidc.ScopeOfflineAccess},
			ResponseType: oidc.ResponseTypeCode,
			Resource:     []string{mcp, api},
		}, "id1")
		require.NoError(t, err)
		require.NoError(t, store.AuthRequestDone(authReq.GetID()))
		require.NoError(t, store.SaveAuthCode(ctx, authReq.GetID(), code))
	}
	newCode(t, "strict-code-1")

	// code exchange narrowed to a granted subset succeeds
	status, body := postToken(t, server, url.Values{
		"grant_type":   {string(oidc.GrantTypeCode)},
		"code":         {"strict-code-1"},
		"redirect_uri": {"https://example.com"},
		"resource":     {mcp},
	}, "web", "secret")
	require.Equal(t, http.StatusOK, status, "body: %s", body)
	tokenResp := new(oidc.AccessTokenResponse)
	require.NoError(t, json.Unmarshal(body, tokenResp))
	require.NotEmpty(t, tokenResp.AccessToken)
	require.NotEmpty(t, tokenResp.RefreshToken, "offline_access must yield a refresh token")

	// the refresh token kept the full grant: refreshing to the other
	// originally granted resource succeeds
	status, body = postToken(t, server, url.Values{
		"grant_type":    {string(oidc.GrantTypeRefreshToken)},
		"refresh_token": {tokenResp.RefreshToken},
		"resource":      {api},
	}, "web", "secret")
	require.Equal(t, http.StatusOK, status, "body: %s", body)

	// refreshing to a resource outside the grant fails
	rotated := new(oidc.AccessTokenResponse)
	require.NoError(t, json.Unmarshal(body, rotated))
	status, body = postToken(t, server, url.Values{
		"grant_type":    {string(oidc.GrantTypeRefreshToken)},
		"refresh_token": {rotated.RefreshToken},
		"resource":      {other},
	}, "web", "secret")
	requireInvalidTargetResponse(t, status, body)

	// exchanging a code for a resource outside the grant fails
	newCode(t, "strict-code-2")
	status, body = postToken(t, server, url.Values{
		"grant_type":   {string(oidc.GrantTypeCode)},
		"code":         {"strict-code-2"},
		"redirect_uri": {"https://example.com"},
		"resource":     {other},
	}, "web", "secret")
	requireInvalidTargetResponse(t, status, body)
}

// TestStrictClientCredentialsFlow shows the strict decision for a storage
// request without resource capabilities: the example client_credentials
// request cannot report a grant, so an explicit resource fails when support
// is advertised and is ignored for backwards compatibility when it is not.
func TestStrictClientCredentialsFlow(t *testing.T) {
	const mcp = "https://mcp.example.com/mcp"

	strictProvider := newStrictTestProvider(t)
	strictServer := op.RegisterLegacyServer(
		op.NewLegacyServer(strictProvider, *op.DefaultEndpoints),
		op.AuthorizeCallbackHandler(strictProvider),
	)
	status, body := postToken(t, strictServer, url.Values{
		"grant_type": {string(oidc.GrantTypeClientCredentials)},
		"resource":   {mcp},
	}, "sid1", "verysecret")
	requireInvalidTargetResponse(t, status, body)

	legacyServer := op.RegisterLegacyServer(
		op.NewLegacyServer(testProvider, *op.DefaultEndpoints),
		op.AuthorizeCallbackHandler(testProvider),
	)
	status, body = postToken(t, legacyServer, url.Values{
		"grant_type": {string(oidc.GrantTypeClientCredentials)},
		"resource":   {mcp},
	}, "sid1", "verysecret")
	require.Equal(t, http.StatusOK, status, "legacy providers keep accept-but-ignore: %s", body)
}

// TestStrictDeviceInitiation shows that a provider advertising RFC 8707
// rejects a device authorization request carrying an explicit resource when
// its storage cannot persist the grant, instead of silently dropping it.
func TestStrictDeviceInitiation(t *testing.T) {
	const mcp = "https://mcp.example.com/mcp"

	authorize := func(t *testing.T, provider op.OpenIDProvider, resources ...string) (int, []byte) {
		t.Helper()
		req := &oidc.DeviceAuthorizationRequest{
			Scopes:   []string{"foo", "bar"},
			ClientID: "device",
			Resource: resources,
		}
		values := make(url.Values)
		provider.Encoder().Encode(req, values)
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(values.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r = r.WithContext(op.ContextWithIssuer(r.Context(), testIssuer))
		w := httptest.NewRecorder()
		op.DeviceAuthorizationHandler(provider)(w, r)
		result := w.Result()
		body, err := io.ReadAll(result.Body)
		require.NoError(t, err)
		return result.StatusCode, body
	}

	t.Run("advertised with resource-aware storage succeeds", func(t *testing.T) {
		status, body := authorize(t, newStrictTestProvider(t), mcp)
		require.Less(t, status, 300, "body: %s", body)
	})

	t.Run("advertised without resource-aware storage fails", func(t *testing.T) {
		shared := storage.NewStorage(storage.NewUserStore(testIssuer))
		provider := providerWithStorage(t, true, &deviceStorageWithoutResources{shared, shared})
		status, body := authorize(t, provider, mcp)
		requireInvalidTargetResponse(t, status, body)
	})

	t.Run("unadvertised without resource-aware storage keeps legacy drop", func(t *testing.T) {
		shared := storage.NewStorage(storage.NewUserStore(testIssuer))
		provider := providerWithStorage(t, false, &deviceStorageWithoutResources{shared, shared})
		status, body := authorize(t, provider, mcp)
		require.Less(t, status, 300, "legacy providers keep the historical drop: %s", body)
	})
}

// TestStrictDeviceTokenFlow shows the strict token-side decision in the device
// flow: narrowing to a granted resource succeeds, anything else fails.
func TestStrictDeviceTokenFlow(t *testing.T) {
	const (
		mcp   = "https://mcp.example.com/mcp"
		api   = "https://api.example.com"
		other = "https://other.example.com"
	)
	ctx := context.Background()
	provider := newStrictTestProvider(t)
	store := provider.Storage().(*storage.Storage)

	req := &oidc.DeviceAuthorizationRequest{
		Scopes:   []string{"foo", "bar"},
		ClientID: "device",
		Resource: []string{mcp, api},
	}
	values := make(url.Values)
	provider.Encoder().Encode(req, values)
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(op.ContextWithIssuer(ctx, testIssuer))
	w := httptest.NewRecorder()
	op.DeviceAuthorizationHandler(provider)(w, r)
	require.Less(t, w.Result().StatusCode, 300)
	response := new(oidc.DeviceAuthorizationResponse)
	require.NoError(t, json.NewDecoder(w.Result().Body).Decode(response))
	require.NoError(t, store.CompleteDeviceAuthorization(ctx, response.UserCode, "id1"))

	poll := func(t *testing.T, resources ...string) (int, []byte) {
		t.Helper()
		form := url.Values{
			"grant_type":  {string(oidc.GrantTypeDeviceCode)},
			"device_code": {response.DeviceCode},
		}
		for _, resource := range resources {
			form.Add("resource", resource)
		}
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.SetBasicAuth(url.QueryEscape("device"), url.QueryEscape("secret"))
		r = r.WithContext(op.ContextWithIssuer(ctx, testIssuer))
		w := httptest.NewRecorder()
		op.DeviceAccessToken(w, r, provider)
		result := w.Result()
		body, err := io.ReadAll(result.Body)
		require.NoError(t, err)
		return result.StatusCode, body
	}

	status, body := poll(t, mcp)
	require.Equal(t, http.StatusOK, status, "body: %s", body)

	status, body = poll(t, other)
	requireInvalidTargetResponse(t, status, body)
}
