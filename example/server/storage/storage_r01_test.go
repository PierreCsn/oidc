package storage

// R01 reproduction: a client must not be able to grant itself arbitrary
// resources (RFC 8707) at the authorization endpoint or the device
// authorization endpoint. Requested resources must be checked against a
// per-client policy before the grant is persisted; anything outside the
// policy fails with `invalid_target` and persists nothing.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

const (
	r01mcp   = "https://mcp.example.com/mcp"
	r01api   = "https://api.example.com"
	r01other = "https://other.example.com"
)

func requireR01InvalidTarget(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	var oidcErr *oidc.Error
	require.True(t, errors.As(err, &oidcErr), "error must be an *oidc.Error, got %T (%v)", err, err)
	assert.Equal(t, oidc.InvalidTarget, oidcErr.ErrorType)
}

// r01WebStore returns a Storage holding a single web client with the given
// resource policy. A nil policy means the client has no policy (legacy,
// unchecked); a non-nil policy (possibly empty) is enforced.
func r01WebStore(policy []string) *Storage {
	client := WebClient("web", "secret")
	client.allowedResources = policy
	return NewStorageWithClients(
		NewUserStore("http://test.example.com"),
		map[string]*Client{"web": client},
	)
}

func r01DeviceStore(policy []string) *Storage {
	client := DeviceClient("device", "secret")
	client.allowedResources = policy
	return NewStorageWithClients(
		NewUserStore("http://test.example.com"),
		map[string]*Client{"device": client},
	)
}

func r01AuthRequest(clientID string, resources ...string) *oidc.AuthRequest {
	return &oidc.AuthRequest{
		ClientID:     clientID,
		RedirectURI:  "https://example.com",
		Scopes:       oidc.SpaceDelimitedArray{oidc.ScopeOpenID},
		ResponseType: oidc.ResponseTypeCode,
		Resource:     resources,
	}
}

func TestR01AuthorizeTimeClientPolicy(t *testing.T) {
	ctx := context.Background()

	t.Run("allowed resource is granted", func(t *testing.T) {
		store := r01WebStore([]string{r01mcp})
		got, err := store.CreateAuthRequest(ctx, r01AuthRequest("web", r01mcp), "id1")
		require.NoError(t, err)
		require.NotNil(t, got)
		grant, ok := got.(op.ResourceRequest)
		require.True(t, ok, "stored auth request must report its grant")
		assert.Equal(t, []string{r01mcp}, grant.GetResource())
	})

	t.Run("resource outside the policy is rejected and persists nothing", func(t *testing.T) {
		store := r01WebStore([]string{r01mcp})
		got, err := store.CreateAuthRequest(ctx, r01AuthRequest("web", r01api), "id1")
		requireR01InvalidTarget(t, err)
		assert.Nil(t, got)
		assert.Empty(t, store.authRequests, "no grant may be kept after refusal")
	})

	t.Run("subset of a multi-resource policy is granted", func(t *testing.T) {
		store := r01WebStore([]string{r01mcp, r01api})
		got, err := store.CreateAuthRequest(ctx, r01AuthRequest("web", r01mcp), "id1")
		require.NoError(t, err)
		grant, ok := got.(op.ResourceRequest)
		require.True(t, ok, "stored auth request must report its grant")
		assert.Equal(t, []string{r01mcp}, grant.GetResource())
	})

	t.Run("explicit empty policy denies every resource", func(t *testing.T) {
		store := r01WebStore([]string{})
		got, err := store.CreateAuthRequest(ctx, r01AuthRequest("web", r01mcp), "id1")
		requireR01InvalidTarget(t, err)
		assert.Nil(t, got)
		assert.Empty(t, store.authRequests, "no grant may be kept after refusal")
	})

	t.Run("explicit empty policy allows a resourceless request", func(t *testing.T) {
		store := r01WebStore([]string{})
		got, err := store.CreateAuthRequest(ctx, r01AuthRequest("web"), "id1")
		require.NoError(t, err)
		grant, ok := got.(op.ResourceRequest)
		require.True(t, ok, "stored auth request must report its grant")
		assert.Empty(t, grant.GetResource())
	})

	// Absent policy (nil): legacy behavior, kept for backwards compatibility.
	// Requested resources are persisted unchecked, so a deployment that
	// advertises resource_indicators_supported (RFC 8707) must configure an
	// explicit policy (possibly empty to deny all) on every client instead of
	// relying on this path.
	t.Run("absent policy keeps documented legacy behavior", func(t *testing.T) {
		store := r01WebStore(nil)
		got, err := store.CreateAuthRequest(ctx, r01AuthRequest("web", r01mcp), "id1")
		require.NoError(t, err, "legacy: no policy means no check")
		grant, ok := got.(op.ResourceRequest)
		require.True(t, ok)
		assert.Equal(t, []string{r01mcp}, grant.GetResource())
	})

	t.Run("resourceless request without policy succeeds", func(t *testing.T) {
		store := r01WebStore(nil)
		got, err := store.CreateAuthRequest(ctx, r01AuthRequest("web"), "id1")
		require.NoError(t, err)
		require.NotNil(t, got)
	})
}

func TestR01DeviceTimeClientPolicy(t *testing.T) {
	ctx := context.Background()
	expires := time.Now().Add(5 * time.Minute)

	t.Run("allowed resource is granted", func(t *testing.T) {
		store := r01DeviceStore([]string{r01mcp})
		err := store.StoreDeviceAuthorizationWithResources(ctx, "device", "device-code-1", "user-code-1", expires, []string{"openid"}, []string{r01mcp})
		require.NoError(t, err)
		state, err := store.GetDeviceAuthorizatonState(ctx, "device", "device-code-1")
		require.NoError(t, err)
		assert.Equal(t, []string{r01mcp}, state.GetResource())
	})

	t.Run("resource outside the policy is rejected early and persists nothing", func(t *testing.T) {
		store := r01DeviceStore([]string{r01mcp})
		err := store.StoreDeviceAuthorizationWithResources(ctx, "device", "device-code-2", "user-code-2", expires, []string{"openid"}, []string{r01api})
		requireR01InvalidTarget(t, err)
		assert.Empty(t, store.deviceCodes, "no device state may be kept after refusal")
		assert.Empty(t, store.userCodes, "no device state may be kept after refusal")
		_, err = store.GetDeviceAuthorizatonState(ctx, "device", "device-code-2")
		require.Error(t, err, "refused device code must be unknown")
	})

	t.Run("explicit empty policy denies every resource", func(t *testing.T) {
		store := r01DeviceStore([]string{})
		err := store.StoreDeviceAuthorizationWithResources(ctx, "device", "device-code-3", "user-code-3", expires, []string{"openid"}, []string{r01mcp})
		requireR01InvalidTarget(t, err)
		assert.Empty(t, store.deviceCodes, "no device state may be kept after refusal")
		assert.Empty(t, store.userCodes, "no device state may be kept after refusal")
	})

	t.Run("explicit empty policy allows a resourceless request", func(t *testing.T) {
		store := r01DeviceStore([]string{})
		err := store.StoreDeviceAuthorizationWithResources(ctx, "device", "device-code-4", "user-code-4", expires, []string{"openid"}, nil)
		require.NoError(t, err)
		state, err := store.GetDeviceAuthorizatonState(ctx, "device", "device-code-4")
		require.NoError(t, err)
		assert.Empty(t, state.GetResource())
	})

	// Absent policy (nil): same documented legacy behavior as the
	// authorization endpoint — see TestR01AuthorizeTimeClientPolicy.
	t.Run("absent policy keeps documented legacy behavior", func(t *testing.T) {
		store := r01DeviceStore(nil)
		err := store.StoreDeviceAuthorizationWithResources(ctx, "device", "device-code-5", "user-code-5", expires, []string{"openid"}, []string{r01mcp})
		require.NoError(t, err, "legacy: no policy means no check")
	})
}

// TestR01RefreshOutsideGrantRejected guards the token-time side of the R01
// chain: once the authorize-time grant is policy-checked, a refresh that
// targets a resource outside that grant must fail with `invalid_target`,
// while a refresh to a granted resource still succeeds.
func TestR01RefreshOutsideGrantRejected(t *testing.T) {
	ctx := context.Background()
	store := r01WebStore([]string{r01mcp, r01api})

	authReq, err := store.CreateAuthRequest(ctx, r01AuthRequest("web", r01mcp, r01api), "id1")
	require.NoError(t, err)
	tokenReq, ok := authReq.(op.TokenRequest)
	require.True(t, ok, "stored auth request must be usable as a token request")

	_, refreshToken, _, err := store.CreateAccessAndRefreshTokens(ctx, tokenReq, "")
	require.NoError(t, err)

	refreshReq, err := store.TokenRequestByRefreshToken(ctx, refreshToken)
	require.NoError(t, err)
	grant, ok := refreshReq.(op.ResourceRequest)
	require.True(t, ok, "refresh request must report the persisted grant")
	assert.Equal(t, []string{r01mcp, r01api}, grant.GetResource())

	err = op.ValidateTokenRequestResources([]string{r01other}, refreshReq)
	requireR01InvalidTarget(t, err)

	require.NoError(t, op.ValidateTokenRequestResources([]string{r01api}, refreshReq),
		"refresh to a granted resource must stay accepted")
}
