package agent

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

const (
	keyBackendSoftware = "software-pem"
	keyBackendDPAPI    = "windows-dpapi-user"
	keyBackendCNG      = "windows-cng"
	keyBackendTPM      = "windows-cng-tpm"
)

func isCNGKeyBackend(backend string) bool {
	return backend == keyBackendCNG || backend == keyBackendTPM
}

// keyReference is intentionally small and opaque. It is persisted in identity
// metadata, never supplied by the server, and contains no private key bytes.
type keyReference struct {
	Backend   string
	Reference string
}

func (r keyReference) normalized() keyReference {
	if r.Backend == "" {
		r.Backend = keyBackendSoftware
	}
	return r
}

func signerFromPEM(privateKeyPEM []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("private key PEM missing")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key does not implement crypto.Signer")
	}
	return signer, nil
}

func tlsCertificateWithSigner(certificatePEM, privateKeyPEM []byte, signer crypto.Signer) (tls.Certificate, error) {
	if signer != nil {
		var certChain [][]byte
		rest := certificatePEM
		for len(rest) > 0 {
			block, next := pem.Decode(rest)
			if block == nil {
				break
			}
			rest = next
			if block.Type == "CERTIFICATE" {
				certChain = append(certChain, block.Bytes)
			}
		}
		if len(certChain) == 0 {
			return tls.Certificate{}, fmt.Errorf("client certificate PEM missing")
		}
		leaf, err := x509.ParseCertificate(certChain[0])
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("parse client certificate: %w", err)
		}
		if !publicKeysEqual(signer.Public(), leaf.PublicKey) {
			return tls.Certificate{}, fmt.Errorf("client certificate does not match protected private key")
		}
		return tls.Certificate{Certificate: certChain, Leaf: leaf, PrivateKey: signer}, nil
	}
	if len(privateKeyPEM) == 0 {
		return tls.Certificate{}, fmt.Errorf("private key material missing")
	}
	return tls.X509KeyPair(certificatePEM, privateKeyPEM)
}

func prepareStoredKey(root string, privateKeyPEM []byte, ref keyReference) ([]byte, keyReference, error) {
	return protectPrivateKeyPlatform(root, privateKeyPEM, ref.normalized())
}

func restoreStoredKey(root string, stored []byte, ref keyReference) ([]byte, crypto.Signer, error) {
	return unprotectPrivateKeyPlatform(root, stored, ref.normalized())
}
