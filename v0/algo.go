package dpopjwt

import (
	"crypto"
	_ "crypto/sha256" // to register a hash
	_ "crypto/sha512" // to register a hash
)

// Signer is used to sign tokens.
type Signer interface {
	Algorithm() Algorithm
	SignSize() int
	Sign(payload []byte) ([]byte, error)
}

// Verifier is used to verify tokens.
type Verifier interface {
	Algorithm() Algorithm
	Verify(token *Token) error
}

// Algorithm for signing and verifying.
type Algorithm string

func (a Algorithm) String() string { return string(a) }

// Algorithm names for signing and verifying.
const (
	ES256 Algorithm = "ES256"
)

func hashPayload(hash crypto.Hash, payload []byte) ([]byte, error) {
	hasher := hash.New()

	if _, err := hasher.Write(payload); err != nil {
		return nil, err
	}
	signed := hasher.Sum(nil)
	return signed, nil
}

func constTimeAlgEqual(a, b Algorithm) bool {
	return constTimeEqual(a.String(), b.String())
}
