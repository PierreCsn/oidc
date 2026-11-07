package op

// R03 characterization: the strict resource gate (F06) checks capability
// interfaces, not runtime truth of the audience binding.
//
// ValidateTokenRequestResourcesStrict accepts a token request once it
// implements ResourceRequest, CurrentResourceSetter and
// AccessTokenAudienceRequest and the requested resources are within the
// reported grant. It cannot verify that GetAccessTokenAudience actually
// represents the requested resources: a Storage implementation may announce
// the contract yet bind the produced audience to something else (here the
// client alone), and the gate still passes. That limit is documented on
// ValidateTokenRequestResourcesStrict ("What this guarantees / what it
// cannot guarantee") and is not a regression against the agreed F06 contract.
//
// This test pins both sides of the contract so the behavior stays explicit
// and no test name can mislead: the gate accepts on interface presence, and
// the produced audience demonstrably omits the requested resource.
//
// Optional hardening deliberately NOT implemented: an opt-in interface such
// as ValidateAccessTokenAudience(selected []string) error, called by the
// strict gate after SetCurrentResources so a Storage can confirm the
// produced audience covers the selection under its own canonical mapping.
// The library must never enforce naive resource == aud string equality:
// deployments legitimately map resource URIs to audience aliases or logical
// names (RFC 8707 section 2, RFC 9068 sections 3-4), and only the Storage
// knows its mapping. Kept as a maintainer decision; the honest example
// storage binding is pinned by the R02 storage tests instead.

import (
	"slices"
	"testing"
)

func TestR03StrictGateAcceptsDishonestAudience(t *testing.T) {
	const resource = "https://mcp.example.com/mcp"

	// gateCapableRequest implements the full strict contract (grant report,
	// narrowed-selection setter, access audience report) but binds the
	// produced audience to the client alone: exactly the R03 case.
	request := &gateCapableRequest{granted: []string{resource}}

	if err := ValidateTokenRequestResourcesStrict([]string{resource}, request); err != nil {
		t.Fatalf("strict gate must accept on interface presence, got: %v", err)
	}
	if !slices.Equal(request.current, []string{resource}) {
		t.Fatalf("strict gate must deliver the selection, got: %v", request.current)
	}

	// AccessTokenAudience is the exact value CreateJWT puts into the aud
	// claim; here it omits the requested resource the gate just approved.
	audience := AccessTokenAudience(request)
	if slices.Contains(audience, resource) {
		t.Fatalf("fixture no longer reproduces R03: audience %v contains the resource", audience)
	}
	t.Logf("documented F06 limit: gate accepted resource %q while produced audience is %v", resource, audience)
}

func TestR03AdvertisedDispatcherSameLimit(t *testing.T) {
	const resource = "https://mcp.example.com/mcp"

	// The provider-level dispatcher routes advertised providers through the
	// same strict gate, so the documented limit applies end to end.
	request := &gateCapableRequest{granted: []string{resource}}
	if err := validateTokenRequestResources(advertisingProvider{}, []string{resource}, request); err != nil {
		t.Fatalf("advertised dispatcher must accept a capable request, got: %v", err)
	}
	if slices.Contains(AccessTokenAudience(request), resource) {
		t.Fatalf("fixture no longer reproduces R03: audience contains the resource")
	}
}
