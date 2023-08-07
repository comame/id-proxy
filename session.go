package main

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/comame/id-proxy/random"
)

func CreateCookieValue() (string, error) {
	r, err := random.String(16)
	if err != nil {
		return "", err
	}
	return r, nil
}

func CalculateSession(cookie string) string {
	l := CalculateListHash()
	b := sha256.Sum256([]byte(cookie + "." + l))
	return hex.EncodeToString(b[:])
}
