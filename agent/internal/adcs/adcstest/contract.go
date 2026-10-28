// Package adcstest is the contract every ADCS client keeps, whatever reaches ADCS behind it: the fake runs it in CI, and the
// real MS-WCCE client runs it against a lab ADCS, by hand before a release.
package adcstest

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"regexp"
	"slices"
	"testing"

	"certificate-platform/agent/internal/adcs"
)

// Lab is the ADCS a client is held to the contract against, and what is known of it from outside the client.
type Lab struct {
	Client adcs.Client
	// ConfigString names a CA the client reaches.
	ConfigString string
	// UnknownCA names a CA that is not there, on a host that answers; Unreachable, a host that does not.
	UnknownCA, Unreachable string
	// SuppliedTemplate is a template set to "Supply in the request" that the account may enroll on, that takes RSA 2048
	// keys and issues without a CA manager's approval; DirectoryTemplate one that builds its subject from Active Directory.
	SuppliedTemplate, DirectoryTemplate string
	// Name is a DNS name the account may have issued under SuppliedTemplate.
	Name string
}

var oid = regexp.MustCompile(`^\d+(\.\d+)+$`)

// Run holds the client to the contract.
func Run(t *testing.T, lab Lab) {
	ctx := context.Background()

	t.Run("the chain is the CA certificate, then each certificate above it up to a root", func(t *testing.T) {
		chain, err := lab.Client.Chain(ctx, lab.ConfigString)
		if err != nil {
			t.Fatal(err)
		}
		if len(chain) == 0 {
			t.Fatal("no chain")
		}
		certificates := make([]*x509.Certificate, len(chain))
		for i, der := range chain {
			if certificates[i], err = x509.ParseCertificate(der); err != nil {
				t.Fatalf("certificate %d of the chain: %v", i, err)
			}
			if !certificates[i].IsCA {
				t.Fatalf("certificate %d of the chain, %s, is not a CA", i, certificates[i].Subject)
			}
		}
		for i := 0; i+1 < len(certificates); i++ {
			if err := certificates[i].CheckSignatureFrom(certificates[i+1]); err != nil {
				t.Fatalf("%s is not signed by %s, which follows it: %v", certificates[i].Subject, certificates[i+1].Subject, err)
			}
		}
		last := certificates[len(certificates)-1]
		if err := last.CheckSignatureFrom(last); err != nil {
			t.Fatalf("the chain ends at %s, which is not a root: %v", last.Subject, err)
		}
	})

	t.Run("discovery lists the templates with their facts", func(t *testing.T) {
		templates, err := lab.Client.Discover(ctx, lab.ConfigString)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]adcs.Template{}
		for _, tmpl := range templates {
			if tmpl.Name == "" || !oid.MatchString(tmpl.OID) || tmpl.ValidityDays < 1 || tmpl.MinimumKeySize < 0 {
				t.Fatalf("a template's facts are not facts: %+v", tmpl)
			}
			if _, twice := seen[tmpl.Name]; twice {
				t.Fatalf("%s is listed twice", tmpl.Name)
			}
			for _, eku := range tmpl.ExtendedKeyUsages {
				if !oid.MatchString(eku) {
					t.Fatalf("%s has an EKU that is not an OID: %q", tmpl.Name, eku)
				}
			}
			for _, algorithm := range tmpl.KeyAlgorithms {
				if !slices.Contains(adcs.KeyAlgorithms, algorithm) {
					t.Fatalf("%s allows a key algorithm the platform has no name for: %q", tmpl.Name, algorithm)
				}
			}
			seen[tmpl.Name] = tmpl
		}
		supplied, ok := seen[lab.SuppliedTemplate]
		if !ok || !supplied.SubjectFromRequest || !supplied.Enrollable || !supplied.Published {
			t.Fatalf("%s should be listed as published, enrollable and supplying its subject from the request: %+v", lab.SuppliedTemplate, supplied)
		}
		directory, ok := seen[lab.DirectoryTemplate]
		if !ok || directory.SubjectFromRequest {
			t.Fatalf("%s should be listed as building its subject from Active Directory: %+v", lab.DirectoryTemplate, directory)
		}
	})

	t.Run("a CSR submitted under a template that supplies the subject from the request is issued for its key and names", func(t *testing.T) {
		csr, key := request(t, lab.Name)
		submission, err := lab.Client.Submit(ctx, lab.ConfigString, lab.SuppliedTemplate, csr)
		if err != nil {
			t.Fatal(err)
		}
		if submission.Status != adcs.Issued || submission.RequestID == "" {
			t.Fatalf("got %+v, want it issued with a request ID", submission)
		}
		certificate, err := x509.ParseCertificate(submission.Certificate)
		if err != nil {
			t.Fatal(err)
		}
		if !key.PublicKey.Equal(certificate.PublicKey) {
			t.Fatal("the Certificate is not for the CSR's key")
		}
		if !slices.Equal(certificate.DNSNames, []string{lab.Name}) {
			t.Fatalf("the Certificate is for %v, not the names the request supplied", certificate.DNSNames)
		}
		chain, err := lab.Client.Chain(ctx, lab.ConfigString)
		if err != nil {
			t.Fatal(err)
		}
		ca, _ := x509.ParseCertificate(chain[0])
		if err := certificate.CheckSignatureFrom(ca); err != nil {
			t.Fatalf("the Certificate is not signed by the CA certificate: %v", err)
		}
	})

	t.Run("a template the CA does not publish is refused", func(t *testing.T) {
		csr, _ := request(t, lab.Name)
		_, err := lab.Client.Submit(ctx, lab.ConfigString, "NoSuchTemplateAtAll", csr)
		var e *adcs.Error
		if !errors.As(err, &e) || e.Kind != adcs.Rejected || e.Message == "" {
			t.Fatalf("got %v, want a rejected error", err)
		}
	})

	t.Run("a CA that is not there is refused, and a host that does not answer is not reached", func(t *testing.T) {
		csr, _ := request(t, lab.Name)
		for _, c := range []struct{ configString, kind string }{{lab.UnknownCA, adcs.Rejected}, {lab.Unreachable, adcs.Unreachable}} {
			_, chainErr := lab.Client.Chain(ctx, c.configString)
			_, discoverErr := lab.Client.Discover(ctx, c.configString)
			_, submitErr := lab.Client.Submit(ctx, c.configString, lab.SuppliedTemplate, csr)
			for _, err := range []error{chainErr, discoverErr, submitErr} {
				var e *adcs.Error
				if !errors.As(err, &e) || e.Kind != c.kind || e.Message == "" {
					t.Fatalf("%s: got %v, want a %s error", c.configString, err, c.kind)
				}
			}
		}
	})
}

// request is a CSR (DER) for an RSA 2048 key and the name, as the subject's common name and its one DNS name, and the key.
func request(t *testing.T, name string) ([]byte, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Clone(csr), key
}
