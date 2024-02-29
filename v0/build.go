package dpopjwt

import (
	"encoding/base64"
	"encoding/json"
)

// BuilderOption is used to modify builder properties.
type BuilderOption func(*Builder)

// WithKeyID sets `kid` header for token.
func WithKeyID(kid string) BuilderOption {
	return func(b *Builder) { b.header.KeyID = kid }
}

// WithContentType sets `cty` header for token.
func WithContentType(cty string) BuilderOption {
	return func(b *Builder) { b.header.ContentType = cty }
}

// WithTyp sets `typ` header for token with the given string.
func WithTyp(typ string) BuilderOption {
	return func(b *Builder) { b.header.Type = typ }
}

// WithJWK sets `jwk` header with the given JSON Web Key
func WithJWK(jwk JWK) BuilderOption {
	return func(b *Builder) {
		b.header.Jwk = JWK{
			Crv: jwk.Crv,
			Kty: jwk.Kty,
			X:   jwk.X,
			Y:   jwk.Y,
		}
	}
}

// Builder is used to create a new token.
// Safe to use concurrently.
type Builder struct {
	signer    Signer
	header    Header
	headerRaw []byte
}

// NewBuilder returns new instance of Builder.
func NewBuilder(signer Signer, opts ...BuilderOption) *Builder {
	b := &Builder{
		signer: signer,
		header: Header{
			Algorithm: signer.Algorithm(),
			Type:      "dpop+jwt",
		},
	}

	for _, opt := range opts {
		opt(b)
	}

	b.headerRaw = encodeHeader(b.header)

	return b
}

// Build used to create and encode JWT with a provided claims.
// If claims param is of type []byte or string then it's treated as a marshaled JSON.
// In other words you can pass already marshaled claims.
func (b *Builder) Build(claims any) (*Token, error) {
	rawClaims, err := encodeClaims(claims)
	if err != nil {
		return nil, err
	}

	lenH := len(b.headerRaw)
	lenC := b64EncodedLen(len(rawClaims))
	lenS := b64EncodedLen(b.signer.SignSize())

	token := make([]byte, lenH+1+lenC+1+lenS)
	idx := 0
	idx = copy(token[idx:], b.headerRaw)

	// add '.' and append encoded claims
	token[idx] = '.'
	idx++
	b64Encode(token[idx:], rawClaims)
	idx += lenC

	// calculate signature of already written 'header.claims'
	rawSignature, err := b.signer.Sign(token[:idx])
	if err != nil {
		return nil, err
	}

	// add '.' and append encoded signature
	token[idx] = '.'
	idx++
	b64Encode(token[idx:], rawSignature)

	t := &Token{
		raw:       token,
		dot1:      lenH,
		dot2:      lenH + 1 + lenC,
		header:    b.header,
		claims:    rawClaims,
		signature: rawSignature,
	}
	return t, nil
}

func encodeClaims(claims any) ([]byte, error) {
	switch claims := claims.(type) {
	case []byte:
		return claims, nil
	case string:
		return []byte(claims), nil
	default:
		return json.Marshal(claims)
	}
}

func encodeHeader(header Header) []byte {

	buf, _ := header.MarshalJSON()

	encoded := make([]byte, b64EncodedLen(len(buf)))
	b64Encode(encoded, buf)
	return encoded
}

func b64Encode(dst, src []byte) {
	base64.RawURLEncoding.Encode(dst, src)
}

func b64EncodedLen(n int) int {
	return base64.RawURLEncoding.EncodedLen(n)
}
