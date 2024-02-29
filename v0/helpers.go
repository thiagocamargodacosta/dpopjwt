package dpopjwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
)

func ECDSAToJWK(publicKey *ecdsa.PublicKey) (JWK, error) {

	jwk := JWK{}

	jwk.Kty = "EC"

	crv, err := curveName(publicKey.Curve)

	if err != nil {
		fmt.Println(err)
		return jwk, err
	}

	jwk.Crv = crv

	x := base64.URLEncoding.EncodeToString(publicKey.X.Bytes())
	y := base64.URLEncoding.EncodeToString(publicKey.Y.Bytes())

	jwk.X = strings.TrimRight(x, "=")
	jwk.Y = strings.TrimRight(y, "=")

	return jwk, nil
}

func CreateKey() (*ecdsa.PrivateKey, JWK, error) {

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		log.Fatal(err)
		return nil, JWK{}, err
	}

	jwk, err := ECDSAToJWK(&key.PublicKey)

	if err != nil {
		log.Fatal(err)
		return nil, JWK{}, err
	}

	return key, jwk, nil
}

func curveName(curve elliptic.Curve) (string, error) {
	switch curve {

	case elliptic.P256():
		return "P-256", nil

	default:
		return "", errors.New("invalid curve")

	}
}

func CreateExampleDPoPJWT(key *ecdsa.PrivateKey, jwk JWK) *Token {

	jkt, _ := Jkt(jwk)

	signer, _ := NewSignerES(ES256, key)

	claims := &RegisteredClaims{
		Jti:   uuid.NewString(),
		Htm:   "GET",
		Htu:   "https://server.example.com/token",
		Iat:   NewNumericDate(time.Now()),
		Nonce: GenerateNonce(24),
		Cnf: Cnf{
			Jkt: jkt,
		},
	}

	opts := []BuilderOption{
		WithJWK(jwk),
		WithTyp("dpop+jwt"),
	}

	builder := NewBuilder(signer, opts...)

	token, err := builder.Build(claims)

	if err != nil {
		log.Fatal("error while building token:", err)
		return nil
	}

	return token
}
