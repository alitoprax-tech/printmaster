package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"printmaster/common/updateauth"
)

func TestOfflineSignerEndToEnd(t *testing.T) {
	dir := t.TempDir() // Disposable test keys only; never production credentials.
	key := filepath.Join(dir, "private.seed")
	trust := filepath.Join(dir, "trust.json")
	artifact := filepath.Join(dir, "agent.exe")
	output := filepath.Join(dir, "release.json")
	generate := []string{"-action", "generate", "-key", key, "-key-id", "offline", "-out", trust}
	if err := run(generate); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := run(generate); err == nil {
		t.Fatal("existing private key overwritten")
	}
	after, err := os.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("existing private key changed")
	}
	if err := os.WriteFile(artifact, []byte("test-release"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-key", key, "-key-id", "offline", "-out", output, "-artifact", artifact, "-version", "1.2.3"}); err != nil {
		t.Fatal(err)
	}
	keys, err := updateauth.LoadKeyring(trust)
	if err != nil {
		t.Fatal(err)
	}
	m, err := updateauth.LoadManifest(output)
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.Verify(m, updateauth.Target{Component: "agent", Platform: "windows", Arch: "amd64", Channel: "stable"}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := updateauth.VerifyFile(artifact, m); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifact, []byte("test-forgery"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := updateauth.VerifyFile(artifact, m); err == nil {
		t.Fatal("forged release accepted")
	}
	if err := run([]string{"-action", "generate", "-key", filepath.Join(dir, "invalid.seed"), "-key-id", "../invalid", "-out", filepath.Join(dir, "invalid.json")}); err == nil {
		t.Fatal("invalid key identity accepted")
	}
}
