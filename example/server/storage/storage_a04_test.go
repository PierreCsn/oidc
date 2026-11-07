package storage

// A04 characterization (INHERITED, not introduced by this stack): the refresh
// handler validates scopes before resources, and the example refresh wrapper
// writes narrowed scopes straight onto the persisted record. A refresh that
// narrows scopes but requests an ungranted resource is therefore refused with
// invalid_target AFTER the stored scopes changed. The setter and the
// validation order are byte-identical at 5905998. No local fix is applied:
// request-local scopes would also change what a successful narrowed refresh
// persists, which needs maintainer arbitration (tracked separately).

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

const (
	a04resA = "https://a.example.com"
	a04resB = "https://b.example.com"
)

// a04SeedRefreshToken stores a refresh record with the mission's exact
// scenario: scopes openid+email, grant resource A.
func a04SeedRefreshToken(store *Storage, id string) string {
	store.refreshTokens[id] = &RefreshToken{
		ID:            id,
		Token:         id,
		ApplicationID: a01client,
		Audience:      []string{a01client, a04resA},
		UserID:        "id1",
		Scopes:        []string{"openid", "email"},
		Expiration:    time.Now().Add(time.Hour),
		AuthTime:      time.Now(),
		Resource:      []string{a04resA},
	}
	return id
}

func TestA04RejectedRefreshScopeSideEffect_Inherited(t *testing.T) {
	ctx := context.Background()

	t.Run("refused refresh narrows persisted scopes (inherited side effect)", func(t *testing.T) {
		store := a01Store()
		refreshToken := a04SeedRefreshToken(store, "a04-rt")
		require.Equal(t, []string{"openid", "email"},
			store.refreshTokens[refreshToken].Scopes, "seed precondition")

		req, err := store.TokenRequestByRefreshToken(ctx, refreshToken)
		require.NoError(t, err)
		require.NoError(t, op.ValidateRefreshTokenScopes([]string{"openid"}, req))
		err = op.ValidateTokenRequestResources([]string{a04resB}, req)
		require.Error(t, err)
		assert.Equal(t, oidc.InvalidTarget, err.(*oidc.Error).ErrorType)

		assert.Equal(t, []string{"openid"}, store.refreshTokens[refreshToken].Scopes,
			"INHERITED: refusal does not roll the narrowed scopes back")
	})

	t.Run("successful narrowed refresh persists narrowing (coupled semantic)", func(t *testing.T) {
		store := a01Store()
		refreshToken := a04SeedRefreshToken(store, "a04-ok")

		req, err := store.TokenRequestByRefreshToken(ctx, refreshToken)
		require.NoError(t, err)
		require.NoError(t, op.ValidateRefreshTokenScopes([]string{"openid"}, req))
		require.NoError(t, op.ValidateTokenRequestResources([]string{a04resA}, req))
		_, newRefresh, _, err := store.CreateAccessAndRefreshTokens(ctx, req, refreshToken)
		require.NoError(t, err)

		assert.Equal(t, []string{"openid"}, store.refreshTokens[newRefresh].Scopes,
			"narrowing persists on success too: a side-effect fix would change this semantic")
	})
}
