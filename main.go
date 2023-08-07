package main

import (
	"io"
	"log"
	"net/http"
	"net/url"

	"github.com/comame/id-proxy/kvs"
	"github.com/comame/id-proxy/oidc"
	"github.com/comame/readenv-go"
	"github.com/comame/router-go"
)

type envType struct {
	RedisHost   string `env:"REDIS_HOST"`
	RedisPrefix string `env:"REDIS_PREFIX"`

	OIDCIssuer       string `env:"OIDC_ISSUER"`
	OIDCClientID     string `env:"OIDC_CLIENT_ID"`
	OIDCClientSecret string `env:"OIDC_CLIENT_SECRET"`
}

var env envType

func init() {
	readenv.Read(&env)
	if err := oidc.InitializeDiscovery(env.OIDCIssuer); err != nil {
		panic(err)
	}

	kvs.Init(env.RedisHost, env.RedisPrefix)
}

func main() {
	const host = "http://localhost:8080"

	redirectUri, _ := url.JoinPath(host, "/__idproxy/callback")

	// TODO: セッション管理
	// TODO: 設定ファイルからの読み込み
	// TODO: レスポンスからのアクセス許可
	// TODO: リバースプロキシ

	router.Get("/", func(w http.ResponseWriter, r *http.Request) {
		s, err := CreateCookieValue()
		if err != nil {
			panic(err)
		}

		u, err := oidc.GenerateAuthenticationRequestUrl(CalculateSession(s), env.OIDCClientID, redirectUri)
		if err != nil {
			panic(err)
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "__idproxy",
			Value:    s,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
		w.Header().Add("Location", u)
		w.WriteHeader(http.StatusFound)
	})

	router.Get("/__idproxy/callback", func(w http.ResponseWriter, r *http.Request) {
		co, err := r.Cookie("__idproxy")
		if err != nil {
			panic(err)
		}

		payload, err := oidc.CallbackCode(CalculateSession(co.Value), toQueryMap(r), env.OIDCClientID, env.OIDCClientSecret, redirectUri)
		if err != nil {
			log.Println(err)
			io.WriteString(w, "err")
			return
		}

		log.Println(payload)

		io.WriteString(w, "hoge")
	})

	log.Println("http://localhost:8080/")
	http.ListenAndServe(":8080", router.Handler())
}

func toQueryMap(r *http.Request) map[string]string {
	q := r.URL.Query()
	m := make(map[string]string)

	for k, v := range q {
		m[k] = v[0]
	}
	return m
}
