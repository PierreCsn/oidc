package storage

import "time"

// SubjectKind records the trusted provenance of a token subject at issuance:
// human users authenticate through user flows (code, device, refresh,
// exchange) while service clients authenticate through client_credentials.
// Introspection branches on this recorded kind and never infers it from
// user-store lookups or identifier equality (A02). The zero value means the
// kind was not recorded and is treated as human, failing toward the user
// lookup (and to inactive when the user is unknown).
type SubjectKind string

const (
	// SubjectHuman marks tokens issued to a human user.
	SubjectHuman SubjectKind = "human"
	// SubjectMachine marks tokens issued to a service client.
	SubjectMachine SubjectKind = "machine"
)

type Token struct {
	ID             string
	ApplicationID  string
	Subject        string
	RefreshTokenID string
	Audience       []string
	Expiration     time.Time
	Scopes         []string

	// Resource holds the resource indicators (RFC 8707) the token was requested for.
	Resource []string

	// SubjectKind is the trusted subject provenance recorded at issuance.
	SubjectKind SubjectKind
}

type RefreshToken struct {
	ID            string
	Token         string
	AuthTime      time.Time
	AMR           []string
	Audience      []string
	UserID        string
	ApplicationID string
	Expiration    time.Time
	Scopes        []string
	AccessToken   string // Token.ID

	// Resource holds the resource indicators (RFC 8707) the refresh token was
	// granted for. A refresh token request may narrow them down again.
	Resource []string

	// SubjectKind is the trusted subject provenance, copied from the access
	// token at issuance and preserved through rotation.
	SubjectKind SubjectKind
}
