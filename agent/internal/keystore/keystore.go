// Package keystore makes and keeps the private keys of the Managed Certificates this Agent holds the key for. A key is
// made here, kept in a directory only the service account can read, and never leaves the host: the platform is sent only a
// CSR for it (ADR 0002). Keys are filed by Managed Certificate and by the hash of their public key (the SubjectPublicKeyInfo
// the Certificate carries, which Go can read for RSA and ECDSA only), so that the key for a Certificate is found from the
// Certificate itself, and a key made later for the same Managed Certificate would sit beside it.
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

// material is a key made: its PKCS#8, its SubjectPublicKeyInfo, and how to ask for a Certificate for it.
type material struct {
	pkcs8, spki []byte
	csr         func(names []string) ([]byte, error)
}

func generateClassical(algorithm string) (crypto.Signer, error) {
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

func generate(algorithm string) (material, error) {
	if params, ok := mlDsaAlgorithms[algorithm]; ok {
		return generateMLDSA(params)
	}
	key, err := generateClassical(algorithm)
	if err != nil {
		return material{}, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return material{}, err
	}
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return material{}, err
	}
	return material{pkcs8: pkcs8, spki: spki, csr: func(names []string) ([]byte, error) {
		return x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: names[0]}, DNSNames: names}, key)
	}}, nil
}

func (s Store) dirFor(managedCertificateID string) (string, error) {
	// The id becomes a directory name: only what the platform makes ids of.
	if !uuid.MatchString(managedCertificateID) {
		return "", fmt.Errorf("%q is not a Managed Certificate id", managedCertificateID)
	}
	return filepath.Join(s.Dir, managedCertificateID), nil
}

// fileName is the hash of the SubjectPublicKeyInfo as the Certificate carries it. For RSA and ECDSA that is what Go encodes
// a public key as, which is how keys were named before ML-DSA: the CA copies the CSR's encoding into the Certificate.
func fileName(subjectPublicKeyInfo []byte) string {
	sum := sha256.Sum256(subjectPublicKeyInfo)
	return hex.EncodeToString(sum[:]) + ".key"
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
	csrDER, err := key.csr(names)
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
	if err := writeAtomically(filepath.Join(dir, fileName(key.spki)), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key.pkcs8})); err != nil {
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
	path := filepath.Join(dir, fileName(leaf.RawSubjectPublicKeyInfo))
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
