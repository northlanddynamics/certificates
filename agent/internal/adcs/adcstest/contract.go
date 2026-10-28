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
	// ApprovalTemplate is a template like SuppliedTemplate that needs a CA manager's approval.
	ApprovalTemplate string
	// Name is a DNS name the account may have issued under SuppliedTemplate and ApprovalTemplate.
	Name string
	// Manager is the CA manager, who approves and denies pending requests at the CA, outside the client (on a lab host,
	// with `certutil -resubmit` and `certutil -deny`).
	Manager Manager
}

// Manager is what a CA manager does to a pending request, and sees of a revoked Certificate (on a lab host, with
// `certutil -view`).
type Manager interface {
	Approve(requestID string) error
	Deny(requestID, message string) error
	// RevocationReason is the CRLReason code the Certificate of that serial number (hex) is revoked for; false when it is not revoked.
	RevocationReason(serialNumber string) (int, bool, error)
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
		checked, err := lab.Client.Check(ctx, lab.ConfigString, submission.RequestID)
		if err != nil {
			t.Fatal(err)
		}
		if checked.Status != adcs.Issued || checked.RequestID != submission.RequestID || !bytes.Equal(checked.Certificate, submission.Certificate) {
			t.Fatalf("checking an issued request got %+v, want it issued with the same Certificate", checked)
		}
	})

	t.Run("a CSR under a template that needs a CA manager's approval is pending, and checking says so until it is issued", func(t *testing.T) {
		csr, key := request(t, lab.Name)
		submission, err := lab.Client.Submit(ctx, lab.ConfigString, lab.ApprovalTemplate, csr)
		if err != nil {
			t.Fatal(err)
		}
		if submission.Status != adcs.Pending || submission.RequestID == "" || submission.Certificate != nil {
			t.Fatalf("got %+v, want it pending with a request ID and no Certificate", submission)
		}
		checked, err := lab.Client.Check(ctx, lab.ConfigString, submission.RequestID)
		if err != nil {
			t.Fatal(err)
		}
		if checked.Status != adcs.Pending || checked.RequestID != submission.RequestID {
			t.Fatalf("checked before approval, got %+v, want it pending", checked)
		}
		if err := lab.Manager.Approve(submission.RequestID); err != nil {
			t.Fatal(err)
		}
		checked, err = lab.Client.Check(ctx, lab.ConfigString, submission.RequestID)
		if err != nil {
			t.Fatal(err)
		}
		if checked.Status != adcs.Issued || checked.RequestID != submission.RequestID {
			t.Fatalf("checked after approval, got %+v, want it issued", checked)
		}
		certificate, err := x509.ParseCertificate(checked.Certificate)
		if err != nil {
			t.Fatal(err)
		}
		if !key.PublicKey.Equal(certificate.PublicKey) || !slices.Equal(certificate.DNSNames, []string{lab.Name}) {
			t.Fatalf("the Certificate is not for the CSR's key and names: %v", certificate.DNSNames)
		}
	})

	t.Run("a pending request a CA manager denies is denied, with ADCS's disposition message", func(t *testing.T) {
		csr, _ := request(t, lab.Name)
		submission, err := lab.Client.Submit(ctx, lab.ConfigString, lab.ApprovalTemplate, csr)
		if err != nil {
			t.Fatal(err)
		}
		if err := lab.Manager.Deny(submission.RequestID, "not an approved host"); err != nil {
			t.Fatal(err)
		}
		checked, err := lab.Client.Check(ctx, lab.ConfigString, submission.RequestID)
		if err != nil {
			t.Fatal(err)
		}
		if checked.Status != adcs.Denied || checked.RequestID != submission.RequestID || checked.Message == "" || checked.Certificate != nil {
			t.Fatalf("got %+v, want it denied with a message and no Certificate", checked)
		}
	})

	t.Run("a Certificate the CA issued is revoked for the RFC 5280 reason code, and revoking it again changes nothing", func(t *testing.T) {
		csr, _ := request(t, lab.Name)
		submission, err := lab.Client.Submit(ctx, lab.ConfigString, lab.SuppliedTemplate, csr)
		if err != nil {
			t.Fatal(err)
		}
		certificate, err := x509.ParseCertificate(submission.Certificate)
		if err != nil {
			t.Fatal(err)
		}
		serial := certificate.SerialNumber.Text(16)
		if _, revoked, err := lab.Manager.RevocationReason(serial); err != nil || revoked {
			t.Fatalf("revoked before it was asked: %v", err)
		}
		if err := lab.Client.Revoke(ctx, lab.ConfigString, serial, 1); err != nil {
			t.Fatal(err)
		}
		if reason, revoked, err := lab.Manager.RevocationReason(serial); err != nil || !revoked || reason != 1 {
			t.Fatalf("got reason %d, revoked %v, %v; want it revoked for keyCompromise (1)", reason, revoked, err)
		}
		if err := lab.Client.Revoke(ctx, lab.ConfigString, serial, 1); err != nil {
			t.Fatalf("revoking it again: %v", err)
		}
	})

	t.Run("a Certificate the CA does not have is refused revocation", func(t *testing.T) {
		err := lab.Client.Revoke(ctx, lab.ConfigString, "0123456789abcdef0123", 0)
		var e *adcs.Error
		if !errors.As(err, &e) || e.Kind != adcs.Rejected || e.Message == "" {
			t.Fatalf("got %v, want a rejected error", err)
		}
	})

	t.Run("a request the CA does not have is refused", func(t *testing.T) {
		_, err := lab.Client.Check(ctx, lab.ConfigString, "999999999")
		var e *adcs.Error
		if !errors.As(err, &e) || e.Kind != adcs.Rejected || e.Message == "" {
			t.Fatalf("got %v, want a rejected error", err)
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
			_, checkErr := lab.Client.Check(ctx, c.configString, "1")
			revokeErr := lab.Client.Revoke(ctx, c.configString, "01", 0)
			for _, err := range []error{chainErr, discoverErr, submitErr, checkErr, revokeErr} {
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
