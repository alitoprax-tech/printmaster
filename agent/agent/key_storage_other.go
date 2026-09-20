//go:build !windows
// +build !windows

package agent

import "crypto"

func migrateLegacyKeyStoragePlatform(string) error { return nil }

func generateProtectedClientCSR(_ string, agentID, _ string) (*PendingIdentity, error) {
	return generateSoftwareClientCSR(agentID)
}

func protectPrivateKeyPlatform(_ string, privateKeyPEM []byte, ref keyReference) ([]byte, keyReference, error) {
	ref = ref.normalized()
	if ref.Backend == "" {
		ref.Backend = keyBackendSoftware
	}
	return privateKeyPEM, ref, nil
}

func unprotectPrivateKeyPlatform(_ string, stored []byte, ref keyReference) ([]byte, crypto.Signer, error) {
	privateKeyPEM := append([]byte(nil), stored...)
	signer, err := signerFromPEM(privateKeyPEM)
	return privateKeyPEM, signer, err
}
