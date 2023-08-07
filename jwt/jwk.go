package jwt

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
)

type JWK struct {
	Keys []JwkKey `json:"keys"`
}

type JwkKey struct {
	N   string `json:"n"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	E   string `json:"e"`
	Use string `json:"use"`
}

func (key *JwkKey) RsaPubkey() (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, err
	}

	n := new(big.Int).SetBytes(nb)

	ne, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, err
	}

	e := int(new(big.Int).SetBytes(ne).Int64())

	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}
