package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"

	"gopkg.in/yaml.v3"
)

type Site struct {
	Host       string   `yaml:"host"`
	PathPrefix string   `yaml:"pathPrefix"`
	Roles      []string `yaml:"roles"`
}

type SettingList struct {
	Sites []Site `yaml:"sites"`
}

//go:embed list.yml
var settingsList string

var listCache *SettingList

func ReadList() SettingList {
	if listCache != nil {
		return *listCache
	}

	var l SettingList
	if err := yaml.Unmarshal([]byte(settingsList), &l); err != nil {
		panic(err)
	}

	listCache = &l
	return *listCache
}

func CalculateListHash() string {
	b := sha256.Sum256([]byte(settingsList))
	return hex.EncodeToString(b[:])
}
