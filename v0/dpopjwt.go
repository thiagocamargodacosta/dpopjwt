package dpopjwt

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
)

// Public JWK of EC type
type JWK struct {
	Crv string `json:"crv"`
	Kty string `json:"kty"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// Token represents a JWT token.
// See: https://tools.ietf.org/html/rfc7519
type Token struct {
	raw       []byte
	dot1      int
	dot2      int
	signature []byte
	header    Header
	claims    json.RawMessage
}

func (t *Token) String() string {
	return string(t.raw)
}

func (t *Token) Bytes() []byte {
	return t.raw
}

// HeaderPart returns token header part.
func (t *Token) HeaderPart() []byte {
	return t.raw[:t.dot1]
}

// ClaimsPart returns token claims part.
func (t *Token) ClaimsPart() []byte {
	return t.raw[t.dot1+1 : t.dot2]
}

// PayloadPart returns token payload part.
func (t *Token) PayloadPart() []byte {
	return t.raw[:t.dot2]
}

// SignaturePart returns token signature part.
func (t *Token) SignaturePart() []byte {
	return t.raw[t.dot2+1:]
}

// Header returns token's header.
func (t *Token) Header() Header {
	return t.header
}

// Claims returns token's claims.
func (t *Token) Claims() json.RawMessage {
	return t.claims
}

// DecodeClaims into a given parameter.
func (t *Token) DecodeClaims(dst any) error {
	return json.Unmarshal(t.claims, dst)
}

// Signature returns token's signature.
func (t *Token) Signature() []byte {
	return t.signature
}

// unexported method to check that token was created via Parse func.
func (t *Token) isValid() bool {
	return t != nil && len(t.raw) > 0
}

// Header represents a DPoPJWT header data.
type Header struct {
	Type        string    `json:"typ"`
	Algorithm   Algorithm `json:"alg"`
	Jwk         JWK       `json:"jwk"` // stores a JWK public key
	ContentType string    `json:"cty,omitempty"`
	KeyID       string    `json:"kid,omitempty"`
}

// MarshalJSON implements the json.Marshaler interface.
func (h Header) MarshalJSON() ([]byte, error) {
	buf := bytes.Buffer{}

	if h.Type != "" {
		buf.WriteString(`{"typ":"`)
		buf.WriteString(h.Type)
	}
	if h.Algorithm != "" {
		buf.WriteString(`","alg":"`)
		buf.WriteString(string(h.Algorithm))
	}
	if h.ContentType != "" {
		buf.WriteString(`","cty":"`)
		buf.WriteString(h.ContentType)
	}
	if h.KeyID != "" {
		buf.WriteString(`","kid":"`)
		buf.WriteString(h.KeyID)
	}

	buf.WriteString(`","jwk":`)
	jwkJSON, _ := json.Marshal(h.Jwk)
	buf.WriteString(string(jwkJSON))

	buf.WriteString(`}`)

	return buf.Bytes(), nil
}

// Generates a random key of the given bits length.
func GenerateRandomBits(bits int) ([]byte, error) {
	key := make([]byte, bits/8)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}
