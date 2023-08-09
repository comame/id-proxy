package access

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/url"
	"strings"

	"golang.org/x/exp/slices"
	"gopkg.in/yaml.v3"
)

type Site struct {
	Host       string   `yaml:"host"`
	PathPrefix string   `yaml:"pathPrefix"`
	Roles      []string `yaml:"roles"`
	Backend    string   `yaml:"backend"`
}

type SettingList struct {
	Sites []Site `yaml:"sites"`
}

var _listYml string
var _listCache *SettingList

func Initialize(listYml string) SettingList {
	if _listCache != nil {
		return *_listCache
	}

	var l SettingList
	if err := yaml.Unmarshal([]byte(listYml), &l); err != nil {
		panic(err)
	}

	_listYml = listYml
	_listCache = &l
	return *_listCache
}

func CanAccess(requestUrl url.URL, accessMap string) bool {
	siteIndex, err := findMatchSite(requestUrl, *_listCache)
	if err != nil {
		log.Println("対応するサイトが見つからない")
		return false
	}

	m, err := parseAccessMap(accessMap)
	if err != nil {
		log.Println("accessMap のパースに失敗")
		return false
	}

	return slices.Contains(m, siteIndex)
}

func BackendURL(requestUrl url.URL) string {
	siteIndex, err := findMatchSite(requestUrl, *_listCache)
	if err != nil {
		return ""
	}

	return _listCache.Sites[siteIndex].Backend
}

func CalculateListHash() string {
	b := sha256.Sum256([]byte(_listYml))
	return hex.EncodeToString(b[:])
}

func GetAccessMap(roles []string) string {
	m := getAvailableSitesIndex(roles, *_listCache)
	b, _ := json.Marshal(m)
	return string(b)
}

func parseAccessMap(v string) ([]int, error) {
	var j []int
	if err := json.Unmarshal([]byte(v), &j); err != nil {
		return nil, err
	}
	return j, nil
}

func getAvailableSitesIndex(roles []string, list SettingList) []int {
	var r []int
	for i, site := range list.Sites {
		for _, role := range roles {
			if slices.Contains(site.Roles, role) {
				r = append(r, i)
				continue
			}
		}
	}

	return r
}

func findMatchSite(target url.URL, list SettingList) (int, error) {
	for i, site := range list.Sites {
		if target.Host != site.Host {
			continue
		}
		if !strings.HasPrefix(target.Path, site.PathPrefix) {
			continue
		}
		return i, nil
	}

	return 0, errors.New("not found")
}
