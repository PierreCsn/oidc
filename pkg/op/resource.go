package op

import (
	"net/url"
	"slices"
	"strings"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// ResourceRequest is an optional interface which may be implemented by the request
// types returned by [Storage], such as [AuthRequest], [RefreshTokenRequest] or the
// [TokenRequest] of the client credentials grant.
//
// It reports the resources of [RFC 8707] that were granted to the request. The op
// package uses them to check that a `resource` value sent to the token endpoint was
// covered by the original authorization request. The reported grant must stay
// stable while the request is validated: narrowing a token request must not rewrite
// it, see [CurrentResourceSetter].
//
// Implementing this interface opts the request into enforcement: once implemented,
// every requested resource must be part of the reported grant, so an empty grant
// rejects any requested resource with `invalid_target`. A request type that does
// not use resource indicators must not implement it. For the client credentials
// grant, which has no prior authorization request, the method may report the
// resources the client is allowed to request according to local policy.
//
// [RFC 8707]: https://www.rfc-editor.org/rfc/rfc8707
type ResourceRequest interface {
	GetResource() []string
}

// CurrentResourceSetter is an optional interface which may be implemented by the
// request types returned by [Storage], analogous to the `SetCurrentScopes` method of
// [RefreshTokenRequest].
//
// When a token request narrows the granted resources with the `resource` parameter of
// [RFC 8707, section 2.2], the op package passes the requested values to the request
// before the tokens are created, so that the implementation can bind the audience of
// the issued tokens to them. The narrowed selection must be kept apart from the
// original grant: [ResourceRequest.GetResource] keeps reporting what was granted,
// while the values received here select the subset the issued access token is for.
// Only non-empty selections are passed; an omitted `resource` parameter leaves any
// previously stored selection untouched.
//
// [RFC 8707, section 2.2]: https://www.rfc-editor.org/rfc/rfc8707#section-2.2
type CurrentResourceSetter interface {
	SetCurrentResources(resources []string)
}

// CurrentResourceRequest is an optional interface which may be implemented by the
// request types returned by [Storage] alongside [CurrentResourceSetter].
//
// It reports the narrowed `resource` selection of the current token request, as
// received through [CurrentResourceSetter.SetCurrentResources], as opposed to
// [ResourceRequest.GetResource], which keeps reporting the original grant. A nil
// return means the token request did not narrow the grant down, in which case the
// full granted set applies to the issued access token.
type CurrentResourceRequest interface {
	GetCurrentResources() []string
}

// AccessTokenAudienceRequest is an optional interface which may be implemented by
// the request types returned by [Storage].
//
// It reports the audience the issued access token is for. It may differ from
// [TokenRequest.GetAudience] when resource indicators of [RFC 8707] narrow the
// access token down to selected resources. [CreateJWT] prefers it over GetAudience
// when implemented, while [CreateIDToken] keeps using GetAudience: an ID token is
// issued to the OAuth client, which stays its audience.
//
// When a resource selection is effective, implementations SHOULD report the
// selected resources alone, without prepending the client: the client stays
// identified by the `client_id` claim of the access token and by GetAudience.
// Resource servers validate that `aud` contains their own indicator (see
// RFC 9068, section 4), so an audience of unselected parties weakens that
// check. When no resource applies, implementations SHOULD fall back to the
// request audience to preserve historical behavior.
//
// [RFC 8707]: https://www.rfc-editor.org/rfc/rfc8707
type AccessTokenAudienceRequest interface {
	GetAccessTokenAudience() []string
}

// ResourceIndicatorsSupportedProvider is an optional interface a provider may
// implement to report whether it advertises support for the `resource` parameter
// defined by [RFC 8707] (see [Config.ResourceIndicatorsSupported] and the
// `resource_indicators_supported` discovery metadata).
//
// The token endpoint paths of this package select strict resource enforcement
// ([ValidateTokenRequestResourcesStrict]) when the provider implements it and
// reports true, and the backwards-compatible [ValidateTokenRequestResources]
// otherwise. Providers that do not implement it are treated as not advertising
// the feature.
//
// [RFC 8707]: https://www.rfc-editor.org/rfc/rfc8707
type ResourceIndicatorsSupportedProvider interface {
	ResourceIndicatorsSupported() bool
}

// ValidateResourceIndicators validates the values of the `resource` parameter against
// [RFC 8707, section 2]: every value must be an absolute URI and must not include a
// fragment component. Invalid values are rejected with the `invalid_target` error code.
//
// Only the syntax is validated here. Whether a resource is acceptable for the client,
// and how it translates into the audience of the issued tokens, is up to the [Storage]
// implementation, which receives the values as part of the request.
//
// [RFC 8707, section 2]: https://www.rfc-editor.org/rfc/rfc8707#section-2
func ValidateResourceIndicators(resources []string) error {
	for _, resource := range resources {
		if strings.Contains(resource, "#") {
			return oidc.ErrInvalidTarget().
				WithDescription("resource parameter %q must not include a fragment component", resource)
		}
		uri, err := url.Parse(resource)
		if err != nil {
			return oidc.ErrInvalidTarget().WithParent(err).
				WithDescription("resource parameter %q is not a valid URI", resource)
		}
		if !uri.IsAbs() {
			return oidc.ErrInvalidTarget().
				WithDescription("resource parameter %q must be an absolute URI", resource)
		}
	}
	return nil
}

// ValidateTokenRequestResources validates the `resource` values of a token request
// against [RFC 8707, section 2.2].
//
// Besides the syntax checked by [ValidateResourceIndicators], every requested value
// must be one of the resources already granted to request. The grant is reported
// through the optional [ResourceRequest] interface; once a request type implements
// it, the subset rule always applies, so a request for a resource outside an empty
// grant is rejected with `invalid_target` instead of authorizing an arbitrary
// resource. A request type that implements neither [ResourceRequest] nor
// [CurrentResourceSetter] does not use the feature: syntactically valid resources
// are then accepted for backwards compatibility, but they narrow nothing.
//
// If request implements the optional [CurrentResourceSetter] interface, the requested
// resources are set on it, so that the [Storage] implementation can narrow the audience
// of the issued tokens accordingly. An empty `resource` parameter leaves the granted
// resources untouched, as the RFC requires.
//
// When the provider advertises support for resource indicators (see
// [ResourceIndicatorsSupportedProvider]), the token endpoint paths of this package
// use [ValidateTokenRequestResourcesStrict] instead, which fails closed on
// requests the Storage implementation cannot fully honor. Custom servers that
// advertise the feature SHOULD do the same.
//
// [RFC 8707, section 2.2]: https://www.rfc-editor.org/rfc/rfc8707#section-2.2
func ValidateTokenRequestResources(requestedResources []string, request TokenRequest) error {
	if err := ValidateResourceIndicators(requestedResources); err != nil {
		return err
	}
	if len(requestedResources) == 0 {
		return nil
	}
	if granted, ok := request.(ResourceRequest); ok {
		grantedResources := granted.GetResource()
		for _, resource := range requestedResources {
			if !slices.Contains(grantedResources, resource) {
				return oidc.ErrInvalidTarget().
					WithDescription("resource parameter %q was not granted by the authorization request", resource)
			}
		}
	}
	if setter, ok := request.(CurrentResourceSetter); ok {
		setter.SetCurrentResources(requestedResources)
	}
	return nil
}

// ValidateTokenRequestResourcesStrict validates the `resource` values of a token
// request for providers that advertise support for [RFC 8707]. It behaves like
// [ValidateTokenRequestResources], except that an explicitly requested resource is
// rejected with `invalid_target` unless the request demonstrates the full
// resource-indicator contract: reporting the granted resources
// ([ResourceRequest]), accepting the narrowed selection ([CurrentResourceSetter])
// and reporting the access token audience ([AccessTokenAudienceRequest]).
// Requests that omit `resource` are unaffected, as are providers that do not
// advertise the feature (they keep using [ValidateTokenRequestResources]).
//
// What this guarantees: a token is never issued for an explicitly requested
// resource the Storage implementation cannot check against a grant and select
// for the access token audience. What it cannot guarantee: the Storage
// implementation must still truthfully report the grant, keep the delivered
// selection apart from it, and bind the issued access token audience to the
// selection. Those obligations are documented on the interfaces and demonstrated
// by the example storage.
//
// [RFC 8707]: https://www.rfc-editor.org/rfc/rfc8707
func ValidateTokenRequestResourcesStrict(requestedResources []string, request TokenRequest) error {
	if err := ValidateResourceIndicators(requestedResources); err != nil {
		return err
	}
	if len(requestedResources) == 0 {
		return nil
	}
	granted, ok := request.(ResourceRequest)
	if !ok {
		return oidc.ErrInvalidTarget().
			WithDescription("request does not report the original resource grant")
	}
	setter, ok := request.(CurrentResourceSetter)
	if !ok {
		return oidc.ErrInvalidTarget().
			WithDescription("request does not accept narrowed resources")
	}
	if _, ok := request.(AccessTokenAudienceRequest); !ok {
		return oidc.ErrInvalidTarget().
			WithDescription("request does not report the access token audience")
	}
	grantedResources := granted.GetResource()
	for _, resource := range requestedResources {
		if !slices.Contains(grantedResources, resource) {
			return oidc.ErrInvalidTarget().
				WithDescription("resource parameter %q was not granted by the authorization request", resource)
		}
	}
	setter.SetCurrentResources(requestedResources)
	return nil
}

// advertisesResourceIndicators reports whether provider claims support for the
// `resource` parameter defined by [RFC 8707]. Providers that do not implement
// [ResourceIndicatorsSupportedProvider] are treated as not advertising it.
func advertisesResourceIndicators(provider any) bool {
	supported, ok := provider.(ResourceIndicatorsSupportedProvider)
	return ok && supported.ResourceIndicatorsSupported()
}

// validateTokenRequestResources validates an explicitly requested `resource`
// selection strictly when provider advertises support for [RFC 8707], and with
// the backwards-compatible [ValidateTokenRequestResources] otherwise. All token
// endpoint paths of this package route through it so that every grant reports
// the same decision.
func validateTokenRequestResources(provider any, requestedResources []string, request TokenRequest) error {
	if advertisesResourceIndicators(provider) {
		return ValidateTokenRequestResourcesStrict(requestedResources, request)
	}
	return ValidateTokenRequestResources(requestedResources, request)
}
