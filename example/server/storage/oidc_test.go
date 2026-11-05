package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

func TestAuthRequestResources(t *testing.T) {
	const (
		mcp = "https://mcp.example.com/mcp"
		api = "https://api.example.com"
	)

	t.Run("without resource the audience is the client_id", func(t *testing.T) {
		authReq := authRequestToInternal(&oidc.AuthRequest{ClientID: "web"}, "id1")
		assert.Empty(t, authReq.GetResource())
		assert.Equal(t, []string{"web"}, authReq.GetAudience())
		assert.Equal(t, []string{"web"}, authReq.GetAccessTokenAudience())
	})

	t.Run("the requested resources are added to the access token audience", func(t *testing.T) {
		authReq := authRequestToInternal(&oidc.AuthRequest{
			ClientID: "web",
			Resource: []string{mcp, api},
		}, "id1")
		assert.Equal(t, []string{mcp, api}, authReq.GetResource())
		assert.Equal(t, []string{"web"}, authReq.GetAudience(), "ID tokens stay addressed to the client")
		assert.Equal(t, []string{mcp, api}, authReq.GetAccessTokenAudience())
	})

	t.Run("a token request narrows the access token audience down", func(t *testing.T) {
		authReq := authRequestToInternal(&oidc.AuthRequest{
			ClientID: "web",
			Resource: []string{mcp, api},
		}, "id1")
		authReq.SetCurrentResources([]string{mcp})
		assert.Equal(t, []string{mcp, api}, authReq.GetResource(), "grant stays stable")
		assert.Equal(t, []string{"web"}, authReq.GetAudience())
		assert.Equal(t, []string{mcp}, authReq.GetAccessTokenAudience())
	})
}

func TestRefreshTokenRequestResources(t *testing.T) {
	const mcp = "https://mcp.example.com/mcp"

	request := RefreshTokenRequestFromBusiness(&RefreshToken{
		ApplicationID: "web",
		Audience:      []string{"web", mcp},
		Resource:      []string{mcp},
	})
	assert.Equal(t, []string{"web"}, request.GetAudience(), "ID tokens stay addressed to the client")
	accessAud, ok := request.(op.AccessTokenAudienceRequest)
	require.True(t, ok)
	assert.Equal(t, []string{mcp}, accessAud.GetAccessTokenAudience())

	// a refresh request without any resource keeps the client audience
	stored := RefreshTokenRequestFromBusiness(&RefreshToken{
		ApplicationID: "web",
		Audience:      []string{"web", mcp},
	})
	assert.Equal(t, []string{"web"}, stored.GetAudience())
}
