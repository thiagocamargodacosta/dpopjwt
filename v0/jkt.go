package dpopjwt

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
)

func Jkt(jwk JWK) (string, error) {

	jwkFields := JWK{
		Kty: jwk.Kty,
		Crv: jwk.Crv,
		X:   jwk.X,
		Y:   jwk.Y,
	}

	jwkFieldsJSON, err := json.Marshal(jwkFields)

	if err != nil {
		return "", err
	}

	sha256Hash := sha256.Sum256(jwkFieldsJSON)

	jkt := base64.URLEncoding.EncodeToString(sha256Hash[:])

	return strings.TrimRight(jkt, "="), nil
}
