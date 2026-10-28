package adcs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Fake is an ADCS CA in memory, for tests: an issuing CA under a root, and the templates it publishes. It is reached at
// its config string; a config string for another host is not reached, and one for another CA on its host is refused, as
// ADCS answers them. It issues what is submitted under a template it publishes and the account may enroll on, at once,
// with the request's subject and names and the template's validity.
type Fake struct {
	ConfigString string
	mu           sync.Mutex
	chain        [][]byte
	caKey        *ecdsa.PrivateKey
	ca           *x509.Certificate
	templates    []Template
	nextRequest  int
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
	issuing, _ := x509.ParseCertificate(caDER)
	return &Fake{
		ConfigString: configString,
		chain:        [][]byte{caDER, rootDER},
		caKey:        caKey,
		ca:           issuing,
		nextRequest:  100,
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

// SetTemplate replaces the facts of the template of that name, or adds it.
func (f *Fake) SetTemplate(t Template) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.templates {
		if strings.EqualFold(f.templates[i].Name, t.Name) {
			f.templates[i] = t
			return
		}
	}
	f.templates = append(f.templates, t)
}

func (f *Fake) Submit(_ context.Context, configString, template string, csrDER []byte) (Submission, error) {
	if err := f.reach(configString); err != nil {
		return Submission{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var found *Template
	for i := range f.templates {
		if strings.EqualFold(f.templates[i].Name, template) {
			found = &f.templates[i]
		}
	}
	switch {
	case found == nil || !found.Published:
		return Submission{}, Refused("the requested certificate template is not supported by this CA: %s", template)
	case !found.Enrollable:
		return Submission{}, Refused("access is denied: the account may not enroll on %s", template)
	case !found.SubjectFromRequest:
		return Submission{}, Refused("%s builds the subject from Active Directory", template)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return Submission{}, Refused("the request is not a CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return Submission{}, Refused("the CSR's signature does not verify: %v", err)
	}
	now := time.Now()
	notAfter := now.Add(time.Duration(found.ValidityDays) * 24 * time.Hour)
	if notAfter.After(f.ca.NotAfter) {
		notAfter = f.ca.NotAfter
	}
	ekus := make([]asn1.ObjectIdentifier, 0, len(found.ExtendedKeyUsages))
	for _, eku := range found.ExtendedKeyUsages {
		var oid asn1.ObjectIdentifier
		for _, part := range strings.Split(eku, ".") {
			n, _ := strconv.Atoi(part)
			oid = append(oid, n)
		}
		ekus = append(ekus, oid)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 72))
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		DNSNames:              csr.DNSNames,
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              notAfter,
		UnknownExtKeyUsage:    ekus,
		BasicConstraintsValid: true,
		CRLDistributionPoints: []string{CDPURL},
	}, f.ca, csr.PublicKey, f.caKey)
	if err != nil {
		return Submission{}, Refused("the CA could not issue: %v", err)
	}
	f.nextRequest++
	return Submission{Status: Issued, RequestID: strconv.Itoa(f.nextRequest), Certificate: der}, nil
}
