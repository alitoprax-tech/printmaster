package config

import (
	"net/url"
	"testing"
)

func TestPostgresDSNPreservesCredentials(t *testing.T) {
	cfg := DatabaseConfig{Driver: "postgres", Host: "::1", Port: 5432, Name: "fleet data", User: "user@example", Password: "p@ss:/?#%word", SSLMode: "verify-full"}
	u, err := url.Parse(cfg.BuildDSN())
	if err != nil {
		t.Fatal(err)
	}
	password, _ := u.User.Password()
	if u.User.Username() != cfg.User || password != cfg.Password || u.Hostname() != cfg.Host || u.Path != "/"+cfg.Name || u.Query().Get("sslmode") != cfg.SSLMode {
		t.Fatal("DSN does not round-trip structured connection fields")
	}
}
