package oidc

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"

	"github.com/comame/id-proxy/jwt"
	"golang.org/x/exp/slices"
)

type Discovery struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	JwksURI                          string   `json:"jwks_uri"`
	IdTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodSupported []string `json:"token_endpoint_auth_methods_supported"`
	GrantTypesSupported              []string `json:"grant_types_supported"`
}

var (
	ErrInvalidIssuerFormat    = errors.New("invalid issuer value format")
	ErrFailFetchDiscovery     = errors.New("failed to fetch discovery url")
	ErrInvalidDiscoveryFormat = errors.New("invalid discovery format")

	ErrInvalidAuthorizationEndpointFormat               = errors.New("invalid authorization_endpoint format")
	ErrInvalidTokenEndpointFormat                       = errors.New("invalid token_endpoint format")
	ErrInvalidJwksUriFormat                             = errors.New("invalid jwks_uri format")
	ErrIdTokenSigningAlgValuesSupportedUnsupportedValue = errors.New("id_token_signing_alg_values_supported value is unsupported")
	ErrTokenEndpointAuthMethodSupportedUnsupportedValue = errors.New("token_endpoint_auth_methods_supported value is unsupported")
	ErrGrantTypesSupportedUnsupportedValue              = errors.New("grant_types_supported value is unsupported")

	ErrFailFetchJwk     = errors.New("failed to fetch jwk")
	ErrInvalidJwkFormat = errors.New("invalid jwk format")

	ErrUnsupportedKty       = errors.New("unsupported kty value in jwk")
	ErrUnsupportedAlg       = errors.New("unsupported alg value in jwk")
	ErrUnsupportedUse       = errors.New("unsupported use value in jwk")
	ErrSingleKeyIsSupported = errors.New("single key in jwk is currently supported")
)

var cacheDiscovery *Discovery
var cacheJwk *jwt.JWK

func InitializeDiscovery(issuer string) error {
	discovery, err := fetchDisvovery(issuer)
	if err != nil {
		return err
	}

	cacheDiscovery = discovery

	jwk, err := fetchJwk(discovery.JwksURI)
	if err != nil {
		return err
	}

	cacheJwk = jwk

	return nil
}

func GetDiscovery() Discovery {
	if cacheDiscovery == nil {
		panic("call oidc.InitializeDiscovery() first.")
	}

	return *cacheDiscovery
}

func GetJWK() jwt.JWK {
	if cacheJwk == nil {
		panic("call oidc.InitializeDiscovery() first.")
	}

	return *cacheJwk
}

func fetchDisvovery(issuer string) (*Discovery, error) {
	u, err := url.Parse(issuer)
	if err != nil {
		return nil, ErrInvalidIssuerFormat
	}
	u.Path = "/.well-known/openid-configuration"

	res, err := http.Get(u.String())
	if err != nil {
		return nil, ErrFailFetchDiscovery
	}
	if res.StatusCode != http.StatusOK {
		return nil, ErrFailFetchDiscovery
	}

	b, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, ErrFailFetchDiscovery
	}

	var discovery Discovery
	if err := json.Unmarshal(b, &discovery); err != nil {
		return nil, ErrInvalidDiscoveryFormat
	}

	if err := validateDiscovery(discovery); err != nil {
		return nil, err
	}

	return &discovery, nil
}

func validateDiscovery(value Discovery) error {
	if _, err := url.Parse(value.AuthorizationEndpoint); err != nil {
		return ErrInvalidAuthorizationEndpointFormat
	}
	if _, err := url.Parse(value.TokenEndpoint); err != nil {
		return ErrInvalidTokenEndpointFormat
	}
	if _, err := url.Parse(value.JwksURI); err != nil {
		return ErrInvalidJwksUriFormat
	}

	if !slices.Contains(value.IdTokenSigningAlgValuesSupported, "RS256") {
		return ErrIdTokenSigningAlgValuesSupportedUnsupportedValue
	}
	if !slices.Contains(value.TokenEndpointAuthMethodSupported, "client_secret_post") {
		return ErrTokenEndpointAuthMethodSupportedUnsupportedValue
	}
	if !slices.Contains(value.GrantTypesSupported, "authorization_code") {
		return ErrGrantTypesSupportedUnsupportedValue
	}

	return nil
}

func fetchJwk(jwkUrl string) (*jwt.JWK, error) {
	res, err := http.Get(jwkUrl)
	if err != nil {
		return nil, ErrFailFetchJwk
	}
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, ErrFailFetchJwk
	}

	var jwk jwt.JWK
	if err := json.Unmarshal(b, &jwk); err != nil {
		return nil, ErrInvalidJwkFormat
	}

	if err := validateJwk(jwk); err != nil {
		return nil, err
	}

	return &jwk, nil
}

func validateJwk(jwk jwt.JWK) error {
	if len(jwk.Keys) != 1 {
		return ErrSingleKeyIsSupported
	}

	key := jwk.Keys[0]
	if key.Kty != "RSA" {
		return ErrUnsupportedKty
	}
	if key.Alg != "RS256" {
		return ErrUnsupportedAlg
	}
	if key.Use != "sig" {
		return ErrUnsupportedUse
	}

	return nil
}
