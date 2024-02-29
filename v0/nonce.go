package dpopjwt

import (
	"errors"
	"math/rand"
	"regexp"
)

func GenerateNonce(length int) string {

	const nqchar = "!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~"

	nonce := make([]byte, length)

	for i := 0; i < length; i++ {

		index := rand.Intn(len(nqchar))
		nonce[i] = nqchar[index]

	}

	return string(nonce)
}

func CheckNonce(nonce string) (bool, error) {

	const pattern = `^(?:!|[\#\$\%\&\'\(\)\*\+\,\-\.\/]|[0-9]|[\:\;\<\=\>\?\@]|[A-Za-z]|[\[\]\^_\x60\{\\|\}\~])+$`

	re := regexp.MustCompile(pattern)

	if re.MatchString(nonce) {
		return true, nil
	}

	return false, errors.New("no match")
}
