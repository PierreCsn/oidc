package storage

import (
	"log/slog"
	"slices"
	"time"

	"golang.org/x/text/language"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

const (
	// CustomScope is an example for how to use custom scopes in this library
	//(in this scenario, when requested, it will return a custom claim)
	CustomScope = "custom_scope"

	// CustomClaim is an example for how to return custom claims with this library
	CustomClaim = "custom_claim"

	// CustomScopeImpersonatePrefix is an example scope prefix for passing user id to impersonate using token exchange
	CustomScopeImpersonatePrefix = "custom_scope:impersonate:"
)

type AuthRequest struct {
	ID            string
	CreationDate  time.Time
	ApplicationID string
	CallbackURI   string
	TransferState string
	Prompt        []string
	UiLocales     []language.Tag
	LoginHint     string
	MaxAuthAge    *time.Duration
	UserID        string
	Scopes        []string
	ResponseType  oidc.ResponseType
	ResponseMode  oidc.ResponseMode
	Nonce         string
	CodeChallenge *OIDCCodeChallenge

	// Resource holds the resource indicators (RFC 8707) requested by the client.
	// It is the original grant and stays untouched when a token request
	// narrows it down, so that refresh tokens can remain bound to the full
	// grant as RFC 8707 section 2.2 requires. See currentResources.
	Resource []string

	// currentResources holds the narrowed `resource` selection of the current
	// token request, as received through SetCurrentResources. It is nil when
	// the token request did not narrow the grant down.
	currentResources []string

	done     bool
	authTime time.Time
}

// LogValue allows you to define which fields will be logged.
// Implements the [slog.LogValuer]
func (a *AuthRequest) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", a.ID),
		slog.Time("creation_date", a.CreationDate),
		slog.Any("scopes", a.Scopes),
		slog.String("response_type", string(a.ResponseType)),
		slog.String("app_id", a.ApplicationID),
		slog.String("callback_uri", a.CallbackURI),
	)
}

func (a *AuthRequest) GetID() string {
	return a.ID
}

func (a *AuthRequest) GetACR() string {
	return "" // we won't handle acr in this example
}

func (a *AuthRequest) GetAMR() []string {
	// this example only uses password for authentication
	if a.done {
		return []string{"pwd"}
	}
	return nil
}

// GetAudience reports the audience of ID tokens issued for this request, which
// stays the OAuth client: resource indicators only narrow access tokens.
func (a *AuthRequest) GetAudience() []string {
	return []string{a.ApplicationID}
}

// GetAccessTokenAudience implements the optional op.AccessTokenAudienceRequest
// interface. It binds the access token audience to the effective resource
// selection of the current token request.
func (a *AuthRequest) GetAccessTokenAudience() []string {
	return audienceFromResources(a.ApplicationID, a.effectiveResources())
}

// effectiveResources returns the narrowed `resource` selection of the current
// token request when it narrowed the grant down, otherwise the full granted set.
func (a *AuthRequest) effectiveResources() []string {
	if a.currentResources != nil {
		return a.currentResources
	}
	return a.Resource
}

// GetResource implements the optional op.ResourceRequest interface, which lets the
// op package check a `resource` parameter of a token request against the resources
// that were requested at the authorization endpoint.
func (a *AuthRequest) GetResource() []string {
	return a.Resource
}

// GetCurrentResources implements the optional op.CurrentResourceRequest interface.
// It reports the narrowed `resource` selection of the current token request, or nil
// when the token request did not narrow the grant down.
func (a *AuthRequest) GetCurrentResources() []string {
	return a.currentResources
}

// SetCurrentResources implements the optional op.CurrentResourceSetter interface.
// It is called with the `resource` values of a token request, after they have been
// checked against the resources of the authorization request, so that the audience
// of the issued tokens can be narrowed down to them. The original grant in Resource
// is left untouched.
func (a *AuthRequest) SetCurrentResources(resources []string) {
	a.currentResources = resources
}

func (a *AuthRequest) GetAuthTime() time.Time {
	return a.authTime
}

func (a *AuthRequest) GetClientID() string {
	return a.ApplicationID
}

func (a *AuthRequest) GetCodeChallenge() *oidc.CodeChallenge {
	return CodeChallengeToOIDC(a.CodeChallenge)
}

func (a *AuthRequest) GetNonce() string {
	return a.Nonce
}

func (a *AuthRequest) GetRedirectURI() string {
	return a.CallbackURI
}

func (a *AuthRequest) GetResponseType() oidc.ResponseType {
	return a.ResponseType
}

func (a *AuthRequest) GetResponseMode() oidc.ResponseMode {
	return a.ResponseMode
}

func (a *AuthRequest) GetScopes() []string {
	return a.Scopes
}

func (a *AuthRequest) GetState() string {
	return a.TransferState
}

func (a *AuthRequest) GetSubject() string {
	return a.UserID
}

func (a *AuthRequest) Done() bool {
	return a.done
}

func PromptToInternal(oidcPrompt oidc.SpaceDelimitedArray) []string {
	prompts := make([]string, 0, len(oidcPrompt))
	for _, oidcPrompt := range oidcPrompt {
		switch oidcPrompt {
		case oidc.PromptNone,
			oidc.PromptLogin,
			oidc.PromptConsent,
			oidc.PromptSelectAccount:
			prompts = append(prompts, oidcPrompt)
		}
	}
	return prompts
}

func MaxAgeToInternal(maxAge *uint) *time.Duration {
	if maxAge == nil {
		return nil
	}
	dur := time.Duration(*maxAge) * time.Second
	return &dur
}

func authRequestToInternal(authReq *oidc.AuthRequest, userID string) *AuthRequest {
	var codeChallenge *OIDCCodeChallenge
	if authReq.CodeChallenge != "" {
		codeChallenge = &OIDCCodeChallenge{
			Challenge: authReq.CodeChallenge,
			Method:    string(authReq.CodeChallengeMethod),
		}
	}

	return &AuthRequest{
		CreationDate:  time.Now(),
		ApplicationID: authReq.ClientID,
		CallbackURI:   authReq.RedirectURI,
		TransferState: authReq.State,
		Prompt:        PromptToInternal(authReq.Prompt),
		UiLocales:     authReq.UILocales,
		LoginHint:     authReq.LoginHint,
		MaxAuthAge:    MaxAgeToInternal(authReq.MaxAge),
		UserID:        userID,
		Scopes:        authReq.Scopes,
		ResponseType:  authReq.ResponseType,
		ResponseMode:  authReq.ResponseMode,
		Nonce:         authReq.Nonce,
		CodeChallenge: codeChallenge,
		Resource:      []string(authReq.Resource),
	}
}

type AuthRequestWithSessionState struct {
	*AuthRequest
	SessionState string
}

func (a *AuthRequestWithSessionState) GetSessionState() string {
	return a.SessionState
}

type OIDCCodeChallenge struct {
	Challenge string
	Method    string
}

func CodeChallengeToOIDC(challenge *OIDCCodeChallenge) *oidc.CodeChallenge {
	if challenge == nil {
		return nil
	}
	challengeMethod := oidc.CodeChallengeMethodPlain
	if challenge.Method == "S256" {
		challengeMethod = oidc.CodeChallengeMethodS256
	}
	return &oidc.CodeChallenge{
		Challenge: challenge.Challenge,
		Method:    challengeMethod,
	}
}

// RefreshTokenRequestFromBusiness will simply wrap the storage RefreshToken to implement the op.RefreshTokenRequest interface
func RefreshTokenRequestFromBusiness(token *RefreshToken) op.RefreshTokenRequest {
	return &RefreshTokenRequest{RefreshToken: token}
}

type RefreshTokenRequest struct {
	*RefreshToken

	// currentResources holds the narrowed `resource` selection of the current
	// token request, as received through SetCurrentResources. It lives on the
	// per-request wrapper so that narrowing never rewrites the persisted
	// refresh token grant. It is nil when the token request did not narrow
	// the grant down.
	currentResources []string
}

func (r *RefreshTokenRequest) GetAMR() []string {
	return r.AMR
}

// GetAudience reports the audience of ID tokens issued for this request, which
// stays the OAuth client: resource indicators only narrow access tokens.
func (r *RefreshTokenRequest) GetAudience() []string {
	return []string{r.ApplicationID}
}

// GetAccessTokenAudience implements the optional op.AccessTokenAudienceRequest
// interface. It binds the access token audience to the effective resource
// selection of the current token request.
func (r *RefreshTokenRequest) GetAccessTokenAudience() []string {
	return audienceFromResources(r.ApplicationID, r.effectiveResources())
}

// effectiveResources returns the narrowed `resource` selection of the current
// token request when it narrowed the grant down, otherwise the full granted set.
func (r *RefreshTokenRequest) effectiveResources() []string {
	if r.currentResources != nil {
		return r.currentResources
	}
	return r.Resource
}

// GetResource implements the optional op.ResourceRequest interface. It reports
// the persisted grant, which narrowing a token request never rewrites.
func (r *RefreshTokenRequest) GetResource() []string {
	return r.Resource
}

// GetCurrentResources implements the optional op.CurrentResourceRequest interface.
// It reports the narrowed `resource` selection of the current token request, or nil
// when the token request did not narrow the grant down.
func (r *RefreshTokenRequest) GetCurrentResources() []string {
	return r.currentResources
}

// SetCurrentResources implements the optional op.CurrentResourceSetter interface.
// It only records the selection on the per-request wrapper; the persisted refresh
// token grant stays untouched so rotation preserves it.
func (r *RefreshTokenRequest) SetCurrentResources(resources []string) {
	r.currentResources = resources
}

func (r *RefreshTokenRequest) GetAuthTime() time.Time {
	return r.AuthTime
}

func (r *RefreshTokenRequest) GetClientID() string {
	return r.ApplicationID
}

func (r *RefreshTokenRequest) GetScopes() []string {
	return r.Scopes
}

func (r *RefreshTokenRequest) GetSubject() string {
	return r.UserID
}

func (r *RefreshTokenRequest) SetCurrentScopes(scopes []string) {
	r.Scopes = scopes
}

// clientCredentialsRequest is the TokenRequest of the client credentials grant
// for service clients with an explicit resource policy. The policy plays the
// role of the original grant: a token request may only select resources from
// it, and the access token audience is bound to the selection.
type clientCredentialsRequest struct {
	clientID         string
	scopes           []string
	grantedResources []string
	currentResources []string
}

func (r *clientCredentialsRequest) GetSubject() string    { return r.clientID }
func (r *clientCredentialsRequest) GetAudience() []string { return []string{r.clientID} }
func (r *clientCredentialsRequest) GetScopes() []string   { return r.scopes }

// GetResource implements the optional op.ResourceRequest interface. It reports
// the service client's resource policy.
func (r *clientCredentialsRequest) GetResource() []string { return r.grantedResources }

// GetCurrentResources implements the optional op.CurrentResourceRequest interface.
// It reports the narrowed `resource` selection of the current token request, or nil
// when the token request did not narrow the policy down.
func (r *clientCredentialsRequest) GetCurrentResources() []string {
	return r.currentResources
}

// SetCurrentResources implements the optional op.CurrentResourceSetter interface.
func (r *clientCredentialsRequest) SetCurrentResources(resources []string) {
	r.currentResources = resources
}

// GetAccessTokenAudience implements the optional op.AccessTokenAudienceRequest
// interface. It binds the access token audience to the effective resource
// selection of the current token request.
func (r *clientCredentialsRequest) GetAccessTokenAudience() []string {
	effective := r.grantedResources
	if r.currentResources != nil {
		effective = r.currentResources
	}
	return audienceFromResources(r.clientID, effective)
}

// audienceFromResources shows how a Storage implementation can bind the audience of
// an issued access token to the resource indicators of [RFC 8707] the client asked
// for.
//
// The client_id is always kept alongside the resources. A real implementation
// would first check the requested resources against a policy of the client, and
// would likely restrict the audience of the access token to the resources alone.
// ID tokens are not affected: they stay addressed to the client, see GetAudience.
//
// [RFC 8707]: https://www.rfc-editor.org/rfc/rfc8707
func audienceFromResources(clientID string, resources []string) []string {
	audience := make([]string, 0, len(resources)+1)
	audience = append(audience, clientID)
	for _, resource := range resources {
		if !slices.Contains(audience, resource) {
			audience = append(audience, resource)
		}
	}
	return audience
}

// resourcesFromRequest returns the resource indicators of [RFC 8707] a token request
// was made for, if the request reports any: the narrowed selection of the current
// token request when it narrowed the grant down, otherwise the full granted set.
//
// [RFC 8707]: https://www.rfc-editor.org/rfc/rfc8707
func resourcesFromRequest(request op.TokenRequest) []string {
	if current, ok := request.(op.CurrentResourceRequest); ok {
		if resources := current.GetCurrentResources(); resources != nil {
			return resources
		}
	}
	if resourceRequest, ok := request.(op.ResourceRequest); ok {
		return resourceRequest.GetResource()
	}
	return nil
}
