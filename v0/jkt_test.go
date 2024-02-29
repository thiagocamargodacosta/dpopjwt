package dpopjwt_test

import (
	"testing"

	dpopjwt "github.com/thiagocamargodacosta/dpopjwt/v0"
)

type JktTableTest struct {
	jwk    dpopjwt.JWK
	jkt    string
	expect string
}

func TestJkt(t *testing.T) {

	jwk := dpopjwt.JWK{
		Crv: "P-256",
		Kty: "EC",
		X:   "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
		Y:   "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA",
	}

	res, _ := dpopjwt.Jkt(jwk)

	testCases := []JktTableTest{
		{
			jwk:    jwk,
			jkt:    res,
			expect: "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I",
		},
	}

	for _, tc := range testCases {

		valid := tc.jkt == tc.expect

		if !valid {
			t.Log("tc.jwk:", tc.jwk)
			t.Log("tc.jkt:", tc.jkt)
			t.Log("tc.expect:", tc.expect)
			t.Fatal("unexpected result")
		}

	}
}
