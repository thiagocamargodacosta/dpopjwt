package dpopjwt_test

import (
	"testing"

	dpopjwt "github.com/thiagocamargodacosta/dpopjwt/v0"
)

func TestDPoPProofBuild(t *testing.T) {

	t.Log("Generate key pair")
	key, jwk, _ := dpopjwt.CreateKey()

	t.Log("Craft DPoP JWT with example claims")
	token := dpopjwt.CreateExampleDPoPJWT(key, jwk)

	t.Log("token:", token.String())

	t.Log("Build verifier")
	verifier, err := dpopjwt.NewVerifierES(dpopjwt.ES256, &key.PublicKey)

	if err != nil {
		t.Error("\tError while building verifier")
	}

	t.Log("Parse and verify the token")
	newToken, err := dpopjwt.Parse(token.Bytes(), verifier)

	if err != nil {
		t.Error("\tError while parsing the token:", err)
	}

	t.Log("Verify token signature")

	err = verifier.Verify(newToken)

	if err != nil {
		t.Error("\tFailed to verify token signature. Got:", err)
	}

}
