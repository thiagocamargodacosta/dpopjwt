package dpopjwt

import (
	"crypto/subtle"
	"time"
)

// Cnf represents a single proof-of-possession key
type Cnf struct {
	Jkt string `json:"jkt,omitempty"`
}

// RegisteredClaims represents the minimal claims for DPoP JWT.
// See: https://datatracker.ietf.org/doc/html/rfc9449#name-dpop-proof-jwt-syntax
type RegisteredClaims struct {

	// Jti claim provides a unique identifier for the DPoP Proof JWT
	Jti string `json:"jti"`

	// Htm claim provides the value of the HTTP method of the request to which
	// the JWT is attached
	Htm string `json:"htm"`

	// Htu claim provides the HTTP target URI of the request to which the
	// JWT is attached, without query and fragment parts
	Htu string `json:"htu"`

	// Iat claim provides the creation timestamp of the JWT
	Iat *NumericDate `json:"iat"`

	// Nonce claim provides the authorization server-provided nonce
	Nonce string `json:"nonce,omitempty"`

	Cnf Cnf `json:"cnf,omitempty"`
}

// IsJti reports whether token has a given id.
func (sc *RegisteredClaims) IsJti(jti string) bool {
	return constTimeEqual(sc.Jti, jti)
}

// IsValidIat reports whether a token was created before a given time.
func (sc *RegisteredClaims) IsValidIat(now time.Time) bool {
	return sc.Iat == nil || sc.Iat.Before(now)
}

func constTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
