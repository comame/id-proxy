package main

import (
	_ "embed"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/comame/id-proxy/access"
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

//go:embed list.yml
var listYml string

func init() {
	readenv.Read(&env)
	if err := oidc.InitializeDiscovery(env.OIDCIssuer); err != nil {
		panic(err)
	}

	kvs.Init(env.RedisHost, env.RedisPrefix)
	access.Initialize(listYml)

	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func main() {
	router.Get("/__idproxy/callback", func(w http.ResponseWriter, r *http.Request) {
		r.URL.Host = r.Host
		handleOIDCCallback(w, r)
	})

	router.Get("/*", func(w http.ResponseWriter, r *http.Request) {
		r.URL.Host = r.Host

		c, err := r.Cookie("__idproxy")
		if err != nil {
			log.Println("Cookie がないのでリダイレクト")
			startSessionAndRedirect(w, r)
			return
		}

		accessMap, ok := GetAccessMap(CalculateSession(c.Value))
		if !ok {
			log.Println("accessMap がないのでリダイレクト")
			startSessionAndRedirect(w, r)
			return
		}

		canAccess := access.CanAccess(*r.URL, accessMap)

		if !canAccess {
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, "アクセス権限がありません")
			return
		}

		u, _ := url.Parse(access.BackendURL(*r.URL))

		rp := &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetURL(u)
			},
		}
		rp.ServeHTTP(w, r)
	})

	log.Println("http://localhost:8080/")
	http.ListenAndServe(":8080", router.Handler())
}

func startSessionAndRedirect(w http.ResponseWriter, r *http.Request) {
	redirectUri, _ := url.JoinPath(r.URL.Host, "/__idproxy/callback")

	s, err := CreateCookieValue()
	if err != nil {
		panic(err)
	}

	u, state, err := oidc.GenerateAuthenticationRequestUrl(CalculateSession(s), env.OIDCClientID, "https://"+redirectUri)
	if err != nil {
		panic(err)
	}

	SaveOriginalUrl(state, r.URL.String())

	http.SetCookie(w, &http.Cookie{
		Name:     "__idproxy",
		Value:    s,
		MaxAge:   24 * 3600,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
		Path:     "/",
	})
	w.Header().Add("Location", u)
	w.WriteHeader(http.StatusFound)
}

func handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	toQueryMap := func(r *http.Request) map[string]string {
		q := r.URL.Query()
		m := make(map[string]string)

		for k, v := range q {
			m[k] = v[0]
		}
		return m
	}

	co, err := r.Cookie("__idproxy")
	if err != nil {
		log.Println(err)
		io.WriteString(w, "err")
		return
	}

	redirectUri, _ := url.JoinPath(r.URL.Host, "/__idproxy/callback")
	payload, err := oidc.CallbackCode(CalculateSession(co.Value), toQueryMap(r), env.OIDCClientID, env.OIDCClientSecret, "https://"+redirectUri)
	if err != nil {
		log.Println(err)
		io.WriteString(w, "err")
		return
	}
	log.Println(payload)

	accessMap := access.GetAccessMap(payload.Roles)
	log.Println(accessMap)
	SaveAccessMap(CalculateSession(co.Value), accessMap)

	state, ok := toQueryMap(r)["state"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	red := GetOriginalUrl(state)
	w.Header().Add("Location", red)
	w.WriteHeader(http.StatusFound)
}
