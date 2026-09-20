// Package updateauth verifies releases signed outside the running PrintMaster server.
package updateauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"time"
)

const MaxArtifactBytes int64 = 1 << 30
const maxDocumentBytes = 64 << 10
const signatureDomain = "printmaster-update-manifest/v2\n"

var versionPattern = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// DownloadURL is a transport hint. It is deliberately excluded from the signature
// so authenticated relays can change address; clients must enforce their own origin.
type Manifest struct {
	ManifestVersion string    `json:"manifest_version"`
	Component       string    `json:"component"`
	Version         string    `json:"version"`
	MinorLine       string    `json:"minor_line"`
	Platform        string    `json:"platform"`
	Arch            string    `json:"arch"`
	Channel         string    `json:"channel"`
	SHA256          string    `json:"sha256"`
	SizeBytes       int64     `json:"size_bytes"`
	SourceURL       string    `json:"source_url"`
	DownloadURL     string    `json:"download_url,omitempty"`
	PublishedAt     time.Time `json:"published_at,omitempty"`
	GeneratedAt     time.Time `json:"generated_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	KeyID           string    `json:"key_id"`
	Signature       string    `json:"signature,omitempty"`
}

type Target struct{ Component, Platform, Arch, Channel string }
type Keyring map[string]ed25519.PublicKey

func (m *Manifest) signingBytes() ([]byte, error) {
	if m == nil {
		return nil, fmt.Errorf("manifest required")
	}
	copy := *m
	copy.Signature = ""
	copy.DownloadURL = ""
	body, err := json.Marshal(copy)
	return append([]byte(signatureDomain), body...), err
}

func (m *Manifest) Validate(target Target, now time.Time) error {
	if m == nil || m.ManifestVersion != "2" {
		return fmt.Errorf("signed v2 manifest required")
	}
	if m.Component != target.Component || m.Platform != target.Platform || m.Arch != target.Arch || m.Channel != target.Channel {
		return fmt.Errorf("manifest target mismatch")
	}
	if (m.Component != "agent" && m.Component != "server") || !identifierPattern.MatchString(m.Platform) || !identifierPattern.MatchString(m.Arch) || !identifierPattern.MatchString(m.Channel) || !identifierPattern.MatchString(m.KeyID) {
		return fmt.Errorf("invalid manifest identity")
	}
	if len(m.Version) > 128 || !versionPattern.MatchString(m.Version) {
		return fmt.Errorf("invalid release version")
	}
	hash, err := hex.DecodeString(m.SHA256)
	if err != nil || len(hash) != sha256.Size {
		return fmt.Errorf("invalid artifact SHA256")
	}
	if m.SizeBytes <= 0 || m.SizeBytes > MaxArtifactBytes {
		return fmt.Errorf("invalid artifact size")
	}
	if m.GeneratedAt.IsZero() || m.GeneratedAt.After(now.Add(5*time.Minute)) || !m.ExpiresAt.After(now) || !m.ExpiresAt.After(m.GeneratedAt) || m.ExpiresAt.Sub(m.GeneratedAt) > 90*24*time.Hour {
		return fmt.Errorf("manifest validity interval rejected")
	}
	return nil
}

func (keys Keyring) Verify(m *Manifest, target Target, now time.Time) error {
	if err := m.Validate(target, now); err != nil {
		return err
	}
	key := keys[m.KeyID]
	if len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("release signing key is not locally trusted")
	}
	signature, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("invalid release signature")
	}
	payload, err := m.signingBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, payload, signature) {
		return fmt.Errorf("release signature verification failed")
	}
	return nil
}

// Sign must run on the release signer, never inside the runtime server.
func Sign(m *Manifest, key ed25519.PrivateKey, now time.Time) error {
	if len(key) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid signing key")
	}
	if m == nil {
		return fmt.Errorf("manifest required")
	}
	if err := m.Validate(Target{m.Component, m.Platform, m.Arch, m.Channel}, now); err != nil {
		return err
	}
	payload, err := m.signingBytes()
	if err != nil {
		return err
	}
	m.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, payload))
	return nil
}

func readDocument(path string, value interface{}) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxDocumentBytes+1))
	if err != nil {
		return err
	}
	if len(b) > maxDocumentBytes {
		return fmt.Errorf("manifest/keyring file too large")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return err
	}
	var extra interface{}
	if err := d.Decode(&extra); err != io.EOF {
		return fmt.Errorf("expected one JSON document")
	}
	return nil
}

func LoadKeyring(path string) (Keyring, error) {
	if path == "" {
		return nil, fmt.Errorf("PRINTMASTER_UPDATE_TRUST_FILE must name a locally provisioned keyring")
	}
	var document struct {
		Keys map[string]string `json:"keys"`
	}
	if err := readDocument(path, &document); err != nil {
		return nil, err
	}
	if len(document.Keys) == 0 || len(document.Keys) > 32 {
		return nil, fmt.Errorf("keyring must contain 1 to 32 keys")
	}
	keys := Keyring{}
	for id, encoded := range document.Keys {
		key, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(key) != ed25519.PublicKeySize || !identifierPattern.MatchString(id) {
			return nil, fmt.Errorf("invalid release public key")
		}
		keys[id] = ed25519.PublicKey(key)
	}
	return keys, nil
}

func LoadManifest(path string) (*Manifest, error) {
	var manifest Manifest
	if err := readDocument(path, &manifest); err != nil {
		return nil, err
	}
	return &manifest, nil
}

func VerifyFile(path string, m *Manifest) error {
	if m == nil || m.SizeBytes <= 0 || m.SizeBytes > MaxArtifactBytes {
		return fmt.Errorf("invalid signed artifact size")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, m.SizeBytes+1))
	if err != nil {
		return err
	}
	if n != m.SizeBytes || hex.EncodeToString(h.Sum(nil)) != m.SHA256 {
		return fmt.Errorf("artifact does not match signed size/hash")
	}
	return nil
}
