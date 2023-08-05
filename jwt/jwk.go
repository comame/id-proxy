package jwt

type JWK struct {
	Keys []JwkKeys `json:"keys"`
}

type JwkKeys struct {
	N   string `json:"n"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	E   string `json:"e"`
	Use string `json:"use"`
}
