package releases

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"printmaster/common/updateauth"
)

func (m *Manager) OfflineSigningEnabled() bool { return m.signedManifestDir != "" }

// getOfflineManifest serves only proofs produced by an independently provisioned
// signer. Runtime database signing keys cannot authorize this release format.
func (m *Manager) getOfflineManifest(ctx context.Context, component, platform, arch, channel string) (*AgentUpdateManifest, error) {
	keys, err := updateauth.LoadKeyring(m.trustFile)
	if err != nil {
		return nil, fmt.Errorf("load release trust: %w", err)
	}
	dir, err := os.Open(m.signedManifestDir)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(1025)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(entries) > 1024 {
		return nil, fmt.Errorf("too many offline manifests")
	}
	target := updateauth.Target{Component: component, Platform: platform, Arch: arch, Channel: channel}
	var latest *updateauth.Manifest
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		manifest, err := updateauth.LoadManifest(filepath.Join(m.signedManifestDir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read offline manifest %s: %w", entry.Name(), err)
		}
		if manifest.Component != component || manifest.Platform != platform || manifest.Arch != arch || manifest.Channel != channel {
			continue
		}
		if err := keys.Verify(manifest, target, m.now()); err != nil {
			return nil, fmt.Errorf("offline manifest %s: %w", entry.Name(), err)
		}
		version := parseSemverVersion(manifest.Version)
		if version == nil {
			return nil, fmt.Errorf("invalid offline release version")
		}
		if latest == nil || version.GreaterThan(parseSemverVersion(latest.Version)) {
			latest = manifest
		}
	}
	if latest == nil {
		return nil, fmt.Errorf("no independently signed release available")
	}
	artifact, err := m.store.GetReleaseArtifact(ctx, latest.Component, latest.Version, latest.Platform, latest.Arch)
	if err != nil {
		return nil, fmt.Errorf("signed artifact unavailable: %w", err)
	}
	if artifact == nil || artifact.SHA256 != latest.SHA256 || artifact.SizeBytes != latest.SizeBytes || artifact.Channel != latest.Channel {
		return nil, fmt.Errorf("cached artifact metadata does not match offline signature")
	}
	latest.DownloadURL = "" // Agent downloads through its enrolled server's authenticated route.
	return latest, nil
}
