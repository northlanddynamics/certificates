// Package identity is the Agent's identity: an ECDSA P-256 key that it generates itself and never sends anywhere (ADR 0002),
// and the certificate the platform's Agent identity CA issued for it, kept in a store only the service account may read.
package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// ErrNotRegistered is returned by Load when the store holds no identity: the Agent has not registered.
var ErrNotRegistered = errors.New("this Agent is not registered: run `agent register` first")

// Identity is a key and the certificate issued for it.
type Identity struct {
	Key  *ecdsa.PrivateKey
	Cert *x509.Certificate
	// CertPEM is the certificate as issued.
	CertPEM []byte
}

// TLS is the identity as a client certificate for mTLS.
func (i *Identity) TLS() *tls.Certificate {
	return &tls.Certificate{Certificate: [][]byte{i.Cert.Raw}, PrivateKey: i.Key, Leaf: i.Cert}
}

// Meta is what the Agent remembers about its registration besides its identity.
type Meta struct {
	PlatformURL string `json:"platformUrl"`
	AgentID     string `json:"agentId"`
}

// NewKey generates an identity key.
func NewKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// CSR is a PEM certificate signing request for key. It carries the public key only.
func CSR(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "agent"}}, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// New pairs key with the certificate (PEM) issued for it, or says why they do not belong together.
func New(key *ecdsa.PrivateKey, certPEM []byte) (*Identity, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("the identity certificate is not a PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("the identity certificate cannot be read: %w", err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, errors.New("the identity certificate is not for this Agent's key")
	}
	return &Identity{Key: key, Cert: cert, CertPEM: certPEM}, nil
}

// Store keeps the identity in a directory: the key and the certificate together in one file, which is replaced as a whole
// so that a crash never leaves a key without its certificate, and the registration beside it.
type Store struct{ Dir string }

const (
	identityFile = "identity.pem"
	metaFile     = "agent.json"
)

// Save replaces the stored identity and registration. The directory and files are for the service account alone; on Windows, where modes protect nothing, the state directory's ACL must (the installer sets it).
func (s Store) Save(id *Identity, meta Meta) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(s.Dir, 0o700); err != nil && runtime.GOOS != "windows" {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(id.Key)
	if err != nil {
		return err
	}
	body := append(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), id.CertPEM...)
	if err := writeAtomically(filepath.Join(s.Dir, identityFile), body); err != nil {
		return err
	}
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return writeAtomically(filepath.Join(s.Dir, metaFile), metaJSON)
}

// SaveIdentity replaces the identity only, as a rotation does.
func (s Store) SaveIdentity(id *Identity) error {
	_, meta, err := s.Load()
	if err != nil {
		return err
	}
	return s.Save(id, meta)
}

// Load reads the stored identity. It refuses a store that others on the host can read, as the key in it is the Agent.
func (s Store) Load() (*Identity, Meta, error) {
	path := filepath.Join(s.Dir, identityFile)
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, Meta{}, ErrNotRegistered
	}
	if err != nil {
		return nil, Meta{}, err
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, Meta{}, fmt.Errorf("%s is readable by others (mode %o): it holds the Agent's private key", path, info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, Meta{}, err
	}
	var key *ecdsa.PrivateKey
	var certPEM []byte
	for rest := data; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "PRIVATE KEY":
			key, err = parseKey(block.Bytes)
			if err != nil {
				return nil, Meta{}, err
			}
		case "CERTIFICATE":
			certPEM = pem.EncodeToMemory(block)
		}
	}
	if key == nil || certPEM == nil {
		return nil, Meta{}, fmt.Errorf("%s does not hold a key and a certificate", path)
	}
	id, err := New(key, certPEM)
	if err != nil {
		return nil, Meta{}, err
	}
	metaJSON, err := os.ReadFile(filepath.Join(s.Dir, metaFile))
	if err != nil {
		return nil, Meta{}, err
	}
	var meta Meta
	if err := json.Unmarshal(metaJSON, &meta); err != nil {
		return nil, Meta{}, fmt.Errorf("%s cannot be read: %w", filepath.Join(s.Dir, metaFile), err)
	}
	return id, meta, nil
}

func parseKey(der []byte) (*ecdsa.PrivateKey, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("the identity key cannot be read: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("the identity key is not an ECDSA key")
	}
	return key, nil
}

// writeAtomically writes a file only its owner can read and renames it into place.
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
