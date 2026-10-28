package adcs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"sync"
	"time"
)

// Fake is an ADCS CA in memory, for tests: an issuing CA under a root, and the templates it publishes. It is reached at
// its config string; a config string for another host is not reached, and one for another CA on its host is refused, as
// ADCS answers them.
type Fake struct {
	ConfigString string
	mu           sync.Mutex
	chain        [][]byte
	templates    []Template
	// failure, when set, is how every operation fails, as a CA that is down or refuses the account does.
	failure *Error
}

// CDPURL is the CRL Distribution Point the fake's CA certificate names.
const CDPURL = "http://pki.corp.example/CertEnroll/Corp%20Issuing%20CA.crl"

// NewFake makes a CA at configString, with a root, a CA certificate under it and three templates: one for TLS, one for
// devices that needs a CA manager's approval, and one that builds its subject from Active Directory.
func NewFake(configString string) (*Fake, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	ca := func(serial int64, name string, parent *x509.Certificate, cdp []string) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: name},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(5 * 365 * 24 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			CRLDistributionPoints: cdp,
		}
	}
	rootTemplate := ca(1, "Corp Root CA", nil, nil)
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	root, _ := x509.ParseCertificate(rootDER)
	caDER, err := x509.CreateCertificate(rand.Reader, ca(2, "Corp Issuing CA", root, []string{CDPURL}), root, &caKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	return &Fake{
		ConfigString: configString,
		chain:        [][]byte{caDER, rootDER},
		templates: []Template{
			{Name: "CorpWebServer", OID: "1.3.6.1.4.1.311.21.8.1.1", DisplayName: "Corp Web Server", ExtendedKeyUsages: []string{"1.3.6.1.5.5.7.3.1"}, ValidityDays: 365, MinimumKeySize: 2048, KeyAlgorithms: []string{"rsa", "ecdsa-p256"}, SubjectFromRequest: true, Enrollable: true, Published: true},
			{Name: "CorpDevice", OID: "1.3.6.1.4.1.311.21.8.1.2", DisplayName: "Corp Device", ExtendedKeyUsages: []string{"1.3.6.1.5.5.7.3.2"}, ValidityDays: 730, MinimumKeySize: 2048, KeyAlgorithms: []string{"rsa"}, ManagerApproval: true, SubjectFromRequest: true, Enrollable: true, Published: true},
			{Name: "Workstation", OID: "1.3.6.1.4.1.311.21.8.1.3", DisplayName: "Workstation Authentication", ExtendedKeyUsages: []string{"1.3.6.1.5.5.7.3.2"}, ValidityDays: 365, MinimumKeySize: 2048, KeyAlgorithms: []string{"rsa"}, Enrollable: true, Published: true},
		},
	}, nil
}

// Fail makes every operation fail as err does; nil makes them work again.
func (f *Fake) Fail(err *Error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failure = err
}

func (f *Fake) reach(configString string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failure != nil {
		return f.failure
	}
	host, name, _ := strings.Cut(configString, `\`)
	myHost, myName, _ := strings.Cut(f.ConfigString, `\`)
	if !strings.EqualFold(host, myHost) {
		return NotReached("the RPC server is unavailable at %s", host)
	}
	if !strings.EqualFold(name, myName) {
		return Refused("%s has no CA named %s", host, name)
	}
	return nil
}

func (f *Fake) Chain(_ context.Context, configString string) ([][]byte, error) {
	if err := f.reach(configString); err != nil {
		return nil, err
	}
	return append([][]byte(nil), f.chain...), nil
}

func (f *Fake) Discover(_ context.Context, configString string) ([]Template, error) {
	if err := f.reach(configString); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Template(nil), f.templates...), nil
}
