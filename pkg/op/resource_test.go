package op_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/schema"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

func TestValidateResourceIndicators(t *testing.T) {
	tests := []struct {
		name      string
		resources []string
		wantErr   bool
	}{
		{
			name:      "no resource",
			resources: nil,
		},
		{
			name:      "absolute URI",
			resources: []string{"https://mcp.example.com/mcp"},
		},
		{
			name:      "multiple absolute URIs",
			resources: []string{"https://mcp.example.com/mcp", "urn:example:resource"},
		},
		{
			name:      "query component is allowed",
			resources: []string{"https://mcp.example.com/mcp?tenant=1"},
		},
		{
			name:      "empty value",
			resources: []string{""},
			wantErr:   true,
		},
		{
			name:      "relative reference",
			resources: []string{"/mcp"},
			wantErr:   true,
		},
		{
			name:      "missing scheme",
			resources: []string{"mcp.example.com/mcp"},
			wantErr:   true,
		},
		{
			name:      "fragment component",
			resources: []string{"https://mcp.example.com/mcp#fragment"},
			wantErr:   true,
		},
		{
			name:      "empty fragment component",
			resources: []string{"https://mcp.example.com/mcp#"},
			wantErr:   true,
		},
		{
			name:      "second value invalid",
			resources: []string{"https://mcp.example.com/mcp", "not a uri"},
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := op.ValidateResourceIndicators(tt.resources)
			if !tt.wantErr {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			var oidcErr *oidc.Error
			require.ErrorAs(t, err, &oidcErr)
			assert.Equal(t, oidc.InvalidTarget, oidcErr.ErrorType)
		})
	}
}

// resourceRequest is a minimal op.TokenRequest which reports and narrows
// the granted resource indicators.
type resourceRequest struct {
	resources        []string
	currentResources []string
}

var _ op.CurrentResourceRequest = (*resourceRequest)(nil)
var _ op.AccessTokenAudienceRequest = (*resourceRequest)(nil)

func (r *resourceRequest) GetSubject() string    { return "id1" }
func (r *resourceRequest) GetAudience() []string { return []string{"client1"} }
func (r *resourceRequest) GetScopes() []string   { return []string{"openid"} }
func (r *resourceRequest) GetResource() []string { return r.resources }
func (r *resourceRequest) GetCurrentResources() []string {
	return r.currentResources
}
func (r *resourceRequest) SetCurrentResources(resources []string) {
	r.currentResources = resources
}
func (r *resourceRequest) GetAccessTokenAudience() []string { return []string{"client1"} }

// grantOnlyRequest reports a grant but cannot receive a narrowed selection.
type grantOnlyRequest struct {
	resources []string
}

func (r *grantOnlyRequest) GetSubject() string    { return "id1" }
func (r *grantOnlyRequest) GetAudience() []string { return []string{"client1"} }
func (r *grantOnlyRequest) GetScopes() []string   { return []string{"openid"} }
func (r *grantOnlyRequest) GetResource() []string { return r.resources }

// setterOnlyRequest accepts a narrowed selection without any grant to check it against.
type setterOnlyRequest struct {
	currentResources []string
}

func (r *setterOnlyRequest) GetSubject() string    { return "id1" }
func (r *setterOnlyRequest) GetAudience() []string { return []string{"client1"} }
func (r *setterOnlyRequest) GetScopes() []string   { return []string{"openid"} }
func (r *setterOnlyRequest) SetCurrentResources(resources []string) {
	r.currentResources = resources
}

// grantAndSetterRequest checks and narrows but never reports the access audience.
type grantAndSetterRequest struct {
	resources        []string
	currentResources []string
}

func (r *grantAndSetterRequest) GetSubject() string    { return "id1" }
func (r *grantAndSetterRequest) GetAudience() []string { return []string{"client1"} }
func (r *grantAndSetterRequest) GetScopes() []string   { return []string{"openid"} }
func (r *grantAndSetterRequest) GetResource() []string { return r.resources }
func (r *grantAndSetterRequest) SetCurrentResources(resources []string) {
	r.currentResources = resources
}

// plainRequest is an op.TokenRequest which implements neither op.ResourceRequest
// nor op.CurrentResourceSetter.
type plainRequest struct{}

func (r *plainRequest) GetSubject() string    { return "id1" }
func (r *plainRequest) GetAudience() []string { return []string{"client1"} }
func (r *plainRequest) GetScopes() []string   { return []string{"openid"} }

func TestValidateTokenRequestResources(t *testing.T) {
	tests := []struct {
		name        string
		requested   []string
		granted     []string
		wantErr     bool
		wantCurrent []string
	}{
		{
			name:    "no resource requested",
			granted: []string{"https://mcp.example.com/mcp"},
			wantErr: false,
		},
		{
			name:        "requested resource was granted",
			requested:   []string{"https://mcp.example.com/mcp"},
			granted:     []string{"https://mcp.example.com/mcp", "https://api.example.com"},
			wantCurrent: []string{"https://mcp.example.com/mcp"},
		},
		{
			name:        "all granted resources requested",
			requested:   []string{"https://mcp.example.com/mcp", "https://api.example.com"},
			granted:     []string{"https://mcp.example.com/mcp", "https://api.example.com"},
			wantCurrent: []string{"https://mcp.example.com/mcp", "https://api.example.com"},
		},
		{
			name:      "requested resource was not granted",
			requested: []string{"https://other.example.com"},
			granted:   []string{"https://mcp.example.com/mcp"},
			wantErr:   true,
		},
		{
			name:      "one of the requested resources was not granted",
			requested: []string{"https://mcp.example.com/mcp", "https://other.example.com"},
			granted:   []string{"https://mcp.example.com/mcp"},
			wantErr:   true,
		},
		{
			name:      "invalid syntax",
			requested: []string{"/mcp"},
			granted:   []string{"/mcp"},
			wantErr:   true,
		},
		{
			// An absent grant must not authorize an arbitrary resource: the
			// request implements ResourceRequest, so the subset rule applies
			// and anything outside the (empty) grant is rejected.
			name:      "nothing granted rejects any requested resource",
			requested: []string{"https://mcp.example.com/mcp"},
			granted:   nil,
			wantErr:   true,
		},
		{
			name:      "explicitly empty grant rejects any requested resource",
			requested: []string{"https://mcp.example.com/mcp"},
			granted:   []string{},
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := &resourceRequest{resources: tt.granted}
			err := op.ValidateTokenRequestResources(tt.requested, request)
			if tt.wantErr {
				require.Error(t, err)
				var oidcErr *oidc.Error
				require.ErrorAs(t, err, &oidcErr)
				assert.Equal(t, oidc.InvalidTarget, oidcErr.ErrorType)
				assert.Nil(t, request.currentResources)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantCurrent, request.currentResources)
		})
	}
}

func TestValidateTokenRequestResourcesStrict(t *testing.T) {
	const granted = "https://mcp.example.com/mcp"

	newRequest := func() op.TokenRequest { return &resourceRequest{resources: []string{granted}} }

	t.Run("no resource requested passes without capabilities", func(t *testing.T) {
		require.NoError(t, op.ValidateTokenRequestResourcesStrict(nil, &plainRequest{}))
	})

	t.Run("request without grant report is rejected", func(t *testing.T) {
		err := op.ValidateTokenRequestResourcesStrict([]string{granted}, &plainRequest{})
		requireInvalidTarget(t, err)
	})

	t.Run("grant without narrowing delivery is rejected", func(t *testing.T) {
		err := op.ValidateTokenRequestResourcesStrict(
			[]string{granted}, &grantOnlyRequest{resources: []string{granted}})
		requireInvalidTarget(t, err)
	})

	t.Run("narrowing delivery without grant is rejected", func(t *testing.T) {
		setter := &setterOnlyRequest{}
		err := op.ValidateTokenRequestResourcesStrict([]string{granted}, setter)
		requireInvalidTarget(t, err)
		assert.Nil(t, setter.currentResources, "rejected selection must not be delivered")
	})

	t.Run("missing access audience report is rejected", func(t *testing.T) {
		partial := &grantAndSetterRequest{resources: []string{granted}}
		err := op.ValidateTokenRequestResourcesStrict([]string{granted}, partial)
		requireInvalidTarget(t, err)
		assert.Nil(t, partial.currentResources, "rejected selection must not be delivered")
	})

	t.Run("granted resource is accepted and delivered", func(t *testing.T) {
		request := newRequest()
		require.NoError(t, op.ValidateTokenRequestResourcesStrict([]string{granted}, request))
		assert.Equal(t, []string{granted}, request.(*resourceRequest).currentResources)
		assert.Equal(t, []string{granted}, request.(*resourceRequest).resources, "grant stays stable")
	})

	t.Run("resource outside the grant is rejected without delivery", func(t *testing.T) {
		request := newRequest()
		err := op.ValidateTokenRequestResourcesStrict([]string{"https://other.example.com"}, request)
		requireInvalidTarget(t, err)
		assert.Nil(t, request.(*resourceRequest).currentResources)
	})

	t.Run("empty grant rejects any requested resource", func(t *testing.T) {
		request := &resourceRequest{}
		err := op.ValidateTokenRequestResourcesStrict([]string{granted}, request)
		requireInvalidTarget(t, err)
		assert.Nil(t, request.currentResources)
	})

	t.Run("invalid syntax is rejected", func(t *testing.T) {
		err := op.ValidateTokenRequestResourcesStrict([]string{"/mcp"}, newRequest())
		requireInvalidTarget(t, err)
	})
}

func requireInvalidTarget(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	var oidcErr *oidc.Error
	require.ErrorAs(t, err, &oidcErr)
	assert.Equal(t, oidc.InvalidTarget, oidcErr.ErrorType)
}

func TestValidateTokenRequestResources_withoutResourceInterfaces(t *testing.T) {
	// A request implementing neither optional interface does not use the
	// feature: syntactically valid resources are accepted for backwards
	// compatibility but cannot narrow anything, while invalid syntax is
	// still rejected.
	require.NoError(t, op.ValidateTokenRequestResources(nil, &plainRequest{}))
	require.NoError(t, op.ValidateTokenRequestResources([]string{"https://mcp.example.com/mcp"}, &plainRequest{}))
	require.Error(t, op.ValidateTokenRequestResources([]string{"/mcp"}, &plainRequest{}))
}

func TestParseTokenRequestResource(t *testing.T) {
	decoder := schema.NewDecoder()
	decoder.IgnoreUnknownKeys(true)

	const form = "client_id=myid&client_secret=mysecret&code=abc&refresh_token=xyz" +
		"&resource=https%3A%2F%2Fmcp.example.com%2Fmcp&resource=https%3A%2F%2Fapi.example.com"
	want := []string{"https://mcp.example.com/mcp", "https://api.example.com"}

	t.Run("authorization_code", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		got, err := op.ParseAccessTokenRequest(r, decoder)
		require.NoError(t, err)
		assert.Equal(t, want, got.Resource)
	})

	t.Run("refresh_token", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		got, err := op.ParseRefreshTokenRequest(r, decoder)
		require.NoError(t, err)
		assert.Equal(t, want, got.Resource)
	})

	t.Run("client_credentials", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		got, err := op.ParseClientCredentialsRequest(r, decoder)
		require.NoError(t, err)
		assert.Equal(t, want, got.Resource)
	})
}
