package main

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/comame/id-proxy/access"
	"github.com/comame/id-proxy/kvs"
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
	l := access.CalculateListHash()
	b := sha256.Sum256([]byte(cookie + "." + l))
	return hex.EncodeToString(b[:])
}

func SaveAccessMap(session, accessMap string) error {
	k := "ACCESS:" + session
	if err := kvs.Set(k, accessMap, 3*24*3600); err != nil {
		return err
	}
	return nil
}

func GetAccessMap(session string) (string, bool) {
	k := "ACCESS:" + session
	v, err := kvs.Get(k)
	if err != nil {
		return "", false
	}
	return v, true
}

func SaveOriginalUrl(state, uri string) {
	k := "REDIRECT:" + state
	kvs.Set(k, uri, 600)
}

func GetOriginalUrl(state string) string {
	k := "REDIRECT:" + state
	v, err := kvs.Get(k)
	if err != nil {
		return ""
	}
	return v
}
