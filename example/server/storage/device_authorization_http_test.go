package storage

// HTTP status regression tests for the device authorization endpoint.
//
// An OAuth refusal (`invalid_target`) coming from resource validation or from
// the per-client resource policy must surface as HTTP 400, while a genuine
// storage failure must stay HTTP 500. Both the legacy handler and the new
// Server-based routes are exercised, because they encode errors through
// different paths (RequestError vs WriteError).

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/language"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

const devHTTPIssuer = "https://localhost:9998/"

const (
	devHTTPAllowed = "https://mcp.example.com/mcp"
	devHTTPOther   = "https://api.example.com"
)

func devHTTPConfig(advertise bool) *op.Config {
	return &op.Config{
		CryptoKey:                   sha256.Sum256([]byte("test")),
		CryptoKeyId:                 "key1",
		DefaultLogoutRedirectURI:    "/logged-out",
		CodeMethodS256:              true,
		AuthMethodPost:              true,
		AuthMethodPrivateKeyJWT:     true,
		GrantTypeRefreshToken:       true,
		RequestObjectSupported:      true,
		SupportedClaims:             op.DefaultSupportedClaims,
		SupportedUILocales:          []language.Tag{language.English},
		ResourceIndicatorsSupported: advertise,
		DeviceAuthorization: op.DeviceAuthorizationConfig{
			Lifetime:     5 * time.Minute,
			PollInterval: 5 * time.Second,
			UserFormPath: "/device",
			UserCode:     op.UserCodeBase20,
		},
	}
}

func devHTTPStore(policy []string) *Storage {
	client := DeviceClient("device", "secret")
	client.allowedResources = policy
	return NewStorageWithClients(
		NewUserStore(devHTTPIssuer),
		map[string]*Client{"device": client},
	)
}

func devHTTPProvider(t *testing.T, store op.Storage, advertise bool) op.OpenIDProvider {
	t.Helper()
	keySet := &op.OpenIDKeySet{Storage: store}
	provider, err := op.NewOpenIDProvider(devHTTPIssuer, devHTTPConfig(advertise), store,
		op.WithAllowInsecure(),
		op.WithAccessTokenKeySet(keySet),
		op.WithIDTokenHintKeySet(keySet),
	)
	require.NoError(t, err)
	return provider
}

// doDeviceAuthorizationLegacy issues a device authorization request against
// the legacy handler and returns the HTTP status and raw body.
func doDeviceAuthorizationLegacy(t *testing.T, provider op.OpenIDProvider, resources ...string) (int, string) {
	t.Helper()
	req := &oidc.DeviceAuthorizationRequest{
		Scopes:   []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess},
		ClientID: "device",
		Resource: resources,
	}
	values := make(url.Values)
	provider.Encoder().Encode(req, values)

	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(op.ContextWithIssuer(r.Context(), devHTTPIssuer))

	w := httptest.NewRecorder()
	op.DeviceAuthorizationHandler(provider)(w, r)

	result := w.Result()
	body, err := io.ReadAll(result.Body)
	require.NoError(t, err)
	return result.StatusCode, string(body)
}

// doDeviceAuthorizationServer issues a device authorization request against
// the new Server-based routes and returns the HTTP status and raw body.
func doDeviceAuthorizationServer(t *testing.T, provider op.OpenIDProvider, resources ...string) (int, string) {
	t.Helper()
	server := op.RegisterLegacyServer(
		op.NewLegacyServer(provider, *op.DefaultEndpoints),
		op.AuthorizeCallbackHandler(provider),
	)

	values := url.Values{
		"scope": {oidc.SpaceDelimitedArray{oidc.ScopeOpenID, oidc.ScopeOfflineAccess}.String()},
	}
	for _, resource := range resources {
		values.Add("resource", resource)
	}
	u, err := url.Parse(devHTTPIssuer)
	require.NoError(t, err)
	u.Path = provider.DeviceAuthorizationEndpoint().Relative()

	r := httptest.NewRequest(http.MethodPost, u.String(), strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth("device", "secret")

	w := httptest.NewRecorder()
	server.ServeHTTP(w, r)

	result := w.Result()
	body, err := io.ReadAll(result.Body)
	require.NoError(t, err)
	return result.StatusCode, string(body)
}

// errDeviceStorage forces a genuine internal storage failure on the device
// authorization store calls.
type errDeviceStorage struct {
	*Storage
	err error
}

func (s errDeviceStorage) StoreDeviceAuthorizationWithResources(ctx context.Context, clientID, deviceCode, userCode string, expires time.Time, scopes, resources []string) error {
	return s.err
}

func (s errDeviceStorage) StoreDeviceAuthorization(ctx context.Context, clientID, deviceCode, userCode string, expires time.Time, scopes []string) error {
	return s.err
}

// noResourceDeviceStorage hides the resource-capable store interface to
// simulate a storage that cannot preserve the grant.
type noResourceDeviceStorage struct {
	op.Storage
	op.DeviceAuthorizationStorage
}

func TestDeviceAuthorizationHTTPStatus(t *testing.T) {
	paths := map[string]func(*testing.T, op.OpenIDProvider, ...string) (int, string){
		"legacy": doDeviceAuthorizationLegacy,
		"server": doDeviceAuthorizationServer,
	}

	t.Run("allowed resource succeeds", func(t *testing.T) {
		for name, do := range paths {
			store := devHTTPStore([]string{devHTTPAllowed})
			provider := devHTTPProvider(t, store, true)

			status, body := do(t, provider, devHTTPAllowed)
			require.Less(t, status, 300, "path %s: %s", name, body)
			assert.Contains(t, body, "device_code", "path %s", name)

			state, err := store.GetDeviceAuthorizatonState(context.Background(), "device", deviceCodeFromBody(t, body))
			require.NoError(t, err, "path %s", name)
			assert.Equal(t, []string{devHTTPAllowed}, state.GetResource(), "path %s", name)
		}
	})

	t.Run("forbidden resource is rejected with 400 invalid_target and persists nothing", func(t *testing.T) {
		for name, do := range paths {
			store := devHTTPStore([]string{devHTTPAllowed})
			provider := devHTTPProvider(t, store, true)

			status, body := do(t, provider, devHTTPOther)
			assert.Equal(t, http.StatusBadRequest, status, "path %s: %s", name, body)
			assert.Contains(t, body, string(oidc.InvalidTarget), "path %s", name)
			assert.NotContains(t, body, "device_code", "path %s", name)
			assert.Empty(t, store.deviceCodes, "path %s: no device state may persist after refusal", name)
			assert.Empty(t, store.userCodes, "path %s: no device state may persist after refusal", name)
		}
	})

	t.Run("invalid resource syntax is rejected with 400 invalid_target", func(t *testing.T) {
		for name, do := range paths {
			store := devHTTPStore([]string{devHTTPAllowed})
			provider := devHTTPProvider(t, store, true)

			status, body := do(t, provider, "/not-an-absolute-uri")
			assert.Equal(t, http.StatusBadRequest, status, "path %s: %s", name, body)
			assert.Contains(t, body, string(oidc.InvalidTarget), "path %s", name)
		}
	})

	t.Run("internal storage error stays 500", func(t *testing.T) {
		for name, do := range paths {
			store := errDeviceStorage{Storage: devHTTPStore(nil), err: errors.New("simulated disk failure")}
			provider := devHTTPProvider(t, store, false)

			status, body := do(t, provider)
			assert.Equal(t, http.StatusInternalServerError, status, "path %s: %s", name, body)
			assert.Contains(t, body, string(oidc.ServerError), "path %s", name)
		}
	})

	t.Run("strict mode with incapable storage is rejected with 400 invalid_target", func(t *testing.T) {
		for name, do := range paths {
			inner := devHTTPStore(nil)
			store := noResourceDeviceStorage{Storage: inner, DeviceAuthorizationStorage: inner}
			provider := devHTTPProvider(t, store, true)

			status, body := do(t, provider, devHTTPAllowed)
			assert.Equal(t, http.StatusBadRequest, status, "path %s: %s", name, body)
			assert.Contains(t, body, string(oidc.InvalidTarget), "path %s", name)
		}
	})

	t.Run("legacy mode without resource is unchanged", func(t *testing.T) {
		for name, do := range paths {
			store := devHTTPStore(nil)
			provider := devHTTPProvider(t, store, false)

			status, body := do(t, provider)
			require.Less(t, status, 300, "path %s: %s", name, body)
			assert.Contains(t, body, "device_code", "path %s", name)
		}
	})
}

func deviceCodeFromBody(t *testing.T, body string) string {
	t.Helper()
	var decoded struct {
		DeviceCode string `json:"device_code"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &decoded))
	require.NotEmpty(t, decoded.DeviceCode)
	return decoded.DeviceCode
}
