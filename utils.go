package caddy_logingov

import (
	"crypto/rand"
	"crypto/sha256"
	b64 "encoding/base64"
	"encoding/hex"
	"strings"
)

func randomHex(n int) (string, error) {
	bytes := make([]byte, n)

	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes), nil
}

func genCodeChallenge(length int) (string, string, error) {
	code, err := randomHex(length)
	if err != nil {
		return "", "", err
	}

	sum := sha256.Sum256([]byte(code))

	return code, b64.StdEncoding.EncodeToString(sum[:]), nil
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func hasPrefixInSlice(compare string, list []string) bool {
	for _, item := range list {
		if strings.HasPrefix(compare, item) {
			return true
		}
	}
	return false
}
