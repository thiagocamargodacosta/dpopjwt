package dpopjwt

import (
	"errors"
	"testing"
)

type NonceTableTest struct {
	nonce string
	valid bool
	err   error
}

func TestNonce(t *testing.T) {

	testCases := generateTableTests()

	for _, tc := range testCases {

		valid, err := CheckNonce(tc.nonce)

		if valid != tc.valid && err != tc.err {
			t.Log("tc.nonce:", tc.nonce)
			t.Log("tc.valid:", tc.valid)
			t.Log("tc.err", tc.err)
			t.Log("valid", valid)
			t.Log("err", err)
			t.Fatal("unexpected behaviour")
		}
	}
}

func generateTableTests() []NonceTableTest {

	const nOfTests = 1000
	const nOfTestKind = 4

	noInvalidChar := make([]NonceTableTest, nOfTests)
	invalidAtEnd := make([]NonceTableTest, nOfTests)
	invalidAtStart := make([]NonceTableTest, nOfTests)
	invalidAtMiddle := make([]NonceTableTest, nOfTests)

	for i := 0; i < nOfTests; i++ {

		noInvalidChar[i] = NonceTableTest{
			GenerateNonce(24),
			true,
			nil,
		}

		invalidAtEnd[i] = NonceTableTest{
			GenerateNonce(24) + `"`,
			false,
			errors.New("no match"),
		}

		invalidAtStart[i] = NonceTableTest{
			`"` + GenerateNonce(24),
			false,
			errors.New("no match"),
		}

		invalidAtMiddle[i] = NonceTableTest{
			GenerateNonce(12) + `"` + GenerateNonce(12),
			false,
			errors.New("no match"),
		}
	}

	tests := make([]NonceTableTest, nOfTests*nOfTestKind)

	tests = append(tests, noInvalidChar...)
	tests = append(tests, invalidAtEnd...)
	tests = append(tests, invalidAtStart...)
	tests = append(tests, invalidAtMiddle...)

	return tests
}
