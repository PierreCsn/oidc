package op

import (
	"errors"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type advertisingProvider struct{}

func (advertisingProvider) ResourceIndicatorsSupported() bool { return true }

type silentProvider struct{}

func (silentProvider) ResourceIndicatorsSupported() bool { return false }

type legacyProvider struct{}

type gateCapableRequest struct {
	granted []string
	current []string
}

func (r *gateCapableRequest) GetSubject() string    { return "id1" }
func (r *gateCapableRequest) GetAudience() []string { return []string{"client1"} }
func (r *gateCapableRequest) GetScopes() []string   { return []string{"openid"} }
func (r *gateCapableRequest) GetResource() []string { return r.granted }
func (r *gateCapableRequest) SetCurrentResources(resources []string) {
	r.current = resources
}
func (r *gateCapableRequest) GetAccessTokenAudience() []string { return []string{"client1"} }

type gateGrantOnlyRequest struct {
	granted []string
}

func (r *gateGrantOnlyRequest) GetSubject() string    { return "id1" }
func (r *gateGrantOnlyRequest) GetAudience() []string { return []string{"client1"} }
func (r *gateGrantOnlyRequest) GetScopes() []string   { return []string{"openid"} }
func (r *gateGrantOnlyRequest) GetResource() []string { return r.granted }

type gatePlainRequest struct{}

func (r *gatePlainRequest) GetSubject() string    { return "id1" }
func (r *gatePlainRequest) GetAudience() []string { return []string{"client1"} }
func (r *gatePlainRequest) GetScopes() []string   { return []string{"openid"} }

func TestAdvertisesResourceIndicators(t *testing.T) {
	if !advertisesResourceIndicators(advertisingProvider{}) {
		t.Error("advertising provider must be reported as advertising")
	}
	if advertisesResourceIndicators(silentProvider{}) {
		t.Error("silent provider must not be reported as advertising")
	}
	if advertisesResourceIndicators(legacyProvider{}) {
		t.Error("provider without the interface must not be reported as advertising")
	}
	if advertisesResourceIndicators(nil) {
		t.Error("nil provider must not be reported as advertising")
	}
	provider := &Provider{config: &Config{ResourceIndicatorsSupported: true}}
	if !advertisesResourceIndicators(provider) {
		t.Error("*Provider with the flag set must be reported as advertising")
	}
	provider.config.ResourceIndicatorsSupported = false
	if advertisesResourceIndicators(provider) {
		t.Error("*Provider with the flag unset must not be reported as advertising")
	}
}

func TestValidateTokenRequestResourcesGate(t *testing.T) {
	const granted = "https://mcp.example.com/mcp"

	tests := []struct {
		name      string
		provider  any
		requested []string
		request   TokenRequest
		wantErr   bool
	}{
		{
			name:      "advertised and capable accepts granted resource",
			provider:  advertisingProvider{},
			requested: []string{granted},
			request:   &gateCapableRequest{granted: []string{granted}},
		},
		{
			name:      "advertised and capable rejects resource outside grant",
			provider:  advertisingProvider{},
			requested: []string{"https://other.example.com"},
			request:   &gateCapableRequest{granted: []string{granted}},
			wantErr:   true,
		},
		{
			name:      "advertised without capabilities rejects",
			provider:  advertisingProvider{},
			requested: []string{granted},
			request:   &gatePlainRequest{},
			wantErr:   true,
		},
		{
			name:      "advertised with partial capabilities rejects",
			provider:  advertisingProvider{},
			requested: []string{granted},
			request:   &gateGrantOnlyRequest{granted: []string{granted}},
			wantErr:   true,
		},
		{
			name:      "advertised without requested resource passes",
			provider:  advertisingProvider{},
			request:   &gatePlainRequest{},
		},
		{
			name:      "silent provider keeps legacy accept-but-ignore",
			provider:  silentProvider{},
			requested: []string{granted},
			request:   &gatePlainRequest{},
		},
		{
			name:      "provider without interface keeps legacy accept-but-ignore",
			provider:  legacyProvider{},
			requested: []string{granted},
			request:   &gatePlainRequest{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTokenRequestResources(tt.provider, tt.requested, tt.request)
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				var oidcErr *oidc.Error
				if !errors.As(err, &oidcErr) || oidcErr.ErrorType != oidc.InvalidTarget {
					t.Fatalf("expected invalid_target, got %v", err)
				}
			}
		})
	}
}
