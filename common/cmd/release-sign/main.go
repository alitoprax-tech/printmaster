// release-sign is an offline operator tool. Never install private signing keys
// inside the PrintMaster runtime server or agent data directory.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"printmaster/common/updateauth"
	"regexp"
	"strings"
	"time"
)

func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func run(args []string) error {
	flags := flag.NewFlagSet("release-sign", flag.ContinueOnError)
	action := flags.String("action", "sign", "generate or sign")
	keyPath := flags.String("key", "", "offline private seed file")
	keyID := flags.String("key-id", "", "release signing key identifier")
	output := flags.String("out", "", "new manifest file, or public keyring file for generate")
	artifact := flags.String("artifact", "", "artifact file to sign")
	component := flags.String("component", "agent", "agent or server")
	version := flags.String("version", "", "semantic release version")
	platform := flags.String("platform", "windows", "target OS")
	arch := flags.String("arch", "amd64", "target architecture")
	channel := flags.String("channel", "stable", "release channel")
	days := flags.Int("valid-days", 30, "validity duration (1 to 90 days)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *keyID == "" || *output == "" {
		return fmt.Errorf("-key, -key-id and -out are required")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`).MatchString(*keyID) {
		return fmt.Errorf("invalid key identifier")
	}
	if *action == "generate" {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		publicJSON, err := json.MarshalIndent(map[string]interface{}{"keys": map[string]string{*keyID: base64.StdEncoding.EncodeToString(pub)}}, "", "  ")
		if err != nil {
			return err
		}
		if err := writeNew(*keyPath, []byte(base64.StdEncoding.EncodeToString(key.Seed())+"\n")); err != nil {
			return err
		}
		if err := writeNew(*output, publicJSON); err != nil {
			return err
		}
		fmt.Println("Offline private seed and public keyring created. Keep the private seed off runtime hosts.")
		return nil
	}
	if *action != "sign" || *artifact == "" || *days < 1 || *days > 90 {
		return fmt.Errorf("sign requires -artifact and a validity of 1 to 90 days")
	}
	encoded, err := os.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return fmt.Errorf("invalid private seed file")
	}
	f, err := os.Open(*artifact)
	if err != nil {
		return err
	}
	h := sha256.New()
	size, err := io.Copy(h, io.LimitReader(f, updateauth.MaxArtifactBytes+1))
	f.Close()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	m := &updateauth.Manifest{ManifestVersion: "2", Component: *component, Version: *version, Platform: *platform, Arch: *arch, Channel: *channel, SHA256: hex.EncodeToString(h.Sum(nil)), SizeBytes: size, GeneratedAt: now, ExpiresAt: now.Add(time.Duration(*days) * 24 * time.Hour), KeyID: *keyID}
	if err := updateauth.Sign(m, ed25519.NewKeyFromSeed(seed), now); err != nil {
		return err
	}
	body, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := writeNew(*output, body); err != nil {
		return err
	}
	fmt.Println("Signed release manifest written; no private key is included.")
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
