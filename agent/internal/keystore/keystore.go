// Package keystore makes and keeps the private keys of the Managed Certificates this Agent holds the key for. A key is
// made here, kept in a directory only the service account can read, and never leaves the host: the platform is sent only a
// CSR for it (ADR 0002). Keys are filed by Managed Certificate and by the hash of their public key, so that the key for a
// Certificate is found from the Certificate itself, and a key made later for the same Managed Certificate would sit beside it.
package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
)

// Store keeps keys under Dir.
type Store struct{ Dir string }

// ErrNoKey means the Agent holds no key for the Certificate.
var ErrNoKey = errors.New("this Agent holds no key for that Certificate")

var uuid = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func generate(algorithm string) (crypto.Signer, error) {
	switch algorithm {
	case "ecdsa-p256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ecdsa-p384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "rsa-2048":
		return rsa.GenerateKey(rand.Reader, 2048)
	case "rsa-3072":
		return rsa.GenerateKey(rand.Reader, 3072)
	case "rsa-4096":
		return rsa.GenerateKey(rand.Reader, 4096)
	}
	return nil, fmt.Errorf("the key algorithm %q is not one this Agent makes", algorithm)
}

func (s Store) dirFor(managedCertificateID string) (string, error) {
	// The id becomes a directory name: only what the platform makes ids of.
	if !uuid.MatchString(managedCertificateID) {
		return "", fmt.Errorf("%q is not a Managed Certificate id", managedCertificateID)
	}
	return filepath.Join(s.Dir, managedCertificateID), nil
}

func fileName(publicKey crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]) + ".key", nil
}

// Generate makes a key of the algorithm for the Managed Certificate, stores it, and returns a PEM CSR for it asking for
// the names. The key is stored before the CSR is returned, so a CSR that reaches the platform always has its key here.
func (s Store) Generate(managedCertificateID, algorithm string, names []string) (csrPEM []byte, err error) {
	if len(names) == 0 {
		return nil, errors.New("no names to make a CSR for")
	}
	dir, err := s.dirFor(managedCertificateID)
	if err != nil {
		return nil, err
	}
	key, err := generate(algorithm)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: names[0]}, DNSNames: names}, key)
	if err != nil {
		return nil, err
	}
	name, err := fileName(key.Public())
	if err != nil {
		return nil, err
	}
	// Directories and file for the service account alone; on Windows, where modes protect nothing, the state directory's ACL must (the installer sets it).
	for _, d := range []string{s.Dir, dir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
		if err := os.Chmod(d, 0o700); err != nil && runtime.GOOS != "windows" {
			return nil, err
		}
	}
	if err := writeAtomically(filepath.Join(dir, name), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

// KeyFile is the path of the stored key for the Managed Certificate whose public key is the Certificate's.
func (s Store) KeyFile(managedCertificateID string, leaf *x509.Certificate) (string, error) {
	dir, err := s.dirFor(managedCertificateID)
	if err != nil {
		return "", err
	}
	name, err := fileName(leaf.PublicKey)
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, name)
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrNoKey
		}
		return "", err
	}
	return path, nil
}

func writeAtomically(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
