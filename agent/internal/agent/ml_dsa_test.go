// Seam B for ML-DSA keys: the Agent makes the key and CSR for a Managed Certificate on an ML-DSA Private CA with Cloudflare's
// CIRCL, since Go's own X.509 package can make neither (RFC 9881). What the tests hold it to is what the outside sees: Go's
// CSR parser reads the CSR with its names, the key it stored is the RFC 9881 seed form that OpenSSL 3.5 and Bun read, and a
// Deployment Run hands the script that key for the ML-DSA Certificate that came back. The platform's side of the CSR is in
// server/test/agent-ml-dsa.test.ts, which checks a CSR made by this code.
package agent_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

var mlDsaAlgorithms = []struct {
	name   string
	oid    asn1.ObjectIdentifier
	scheme sign.Scheme
}{
	{"ml-dsa-44", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}, mldsa44.Scheme()},
	{"ml-dsa-65", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}, mldsa65.Scheme()},
	{"ml-dsa-87", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}, mldsa87.Scheme()},
}

type spki struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// rawCSR is a PKCS#10 as the bytes hold it, so that what Go's parser cannot say of an ML-DSA CSR can be read from them.
type rawCSR struct {
	TBS       asn1.RawValue
	Algorithm pkix.AlgorithmIdentifier
	Signature asn1.BitString
}

// noParameters is whether the AlgorithmIdentifier has none: RFC 9881 has the parameters absent, not NULL.
func noParameters(a pkix.AlgorithmIdentifier) bool { return len(a.Parameters.FullBytes) == 0 }

func TestAnMLDSAKeyAndCSRAreMadeThatGoReadsWithItsNames(t *testing.T) {
	for _, alg := range mlDsaAlgorithms {
		t.Run(alg.name, func(t *testing.T) {
			w, logs := relayWorld(t)
			w.stub.Enqueue(generateKeyItem("k1", alg.name, "app.example.test", "*.wild.example.test"))
			w.runUntilReported(1)

			r := w.stub.Results()[0]
			if !r.OK || r.CSR == "" || r.Run != nil {
				t.Fatalf("got %+v", r)
			}
			block, _ := pem.Decode([]byte(r.CSR))
			if block == nil || block.Type != "CERTIFICATE REQUEST" {
				t.Fatalf("not a PEM CSR: %q", r.CSR)
			}

			// Go's parser reads it, names and all; the SAN is in an extensionRequest of the right shape or it would be lost.
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				t.Fatalf("Go does not read the CSR: %v", err)
			}
			if got := strings.Join(csr.DNSNames, ","); got != "app.example.test,*.wild.example.test" {
				t.Fatalf("the CSR asks for %q", got)
			}
			if csr.Subject.CommonName != "app.example.test" {
				t.Fatalf("the common name is %q", csr.Subject.CommonName)
			}

			// The key and the signature are under the RFC 9881 OID, parameters absent, and the signature is pure ML-DSA with an empty context.
			var key spki
			if _, err := asn1.Unmarshal(csr.RawSubjectPublicKeyInfo, &key); err != nil {
				t.Fatal(err)
			}
			if !key.Algorithm.Algorithm.Equal(alg.oid) || !noParameters(key.Algorithm) {
				t.Fatalf("the key is under %v with parameters %x", key.Algorithm.Algorithm, key.Algorithm.Parameters.FullBytes)
			}
			if len(key.PublicKey.Bytes) != alg.scheme.PublicKeySize() {
				t.Fatalf("the public key is %d bytes, want %d", len(key.PublicKey.Bytes), alg.scheme.PublicKeySize())
			}
			var raw rawCSR
			if _, err := asn1.Unmarshal(block.Bytes, &raw); err != nil {
				t.Fatal(err)
			}
			if !raw.Algorithm.Algorithm.Equal(alg.oid) || !noParameters(raw.Algorithm) {
				t.Fatalf("the signature is under %v with parameters %x", raw.Algorithm.Algorithm, raw.Algorithm.Parameters.FullBytes)
			}
			pub, err := alg.scheme.UnmarshalBinaryPublicKey(key.PublicKey.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if !alg.scheme.Verify(pub, csr.RawTBSCertificateRequest, raw.Signature.Bytes, nil) {
				t.Fatal("the CSR's signature does not verify")
			}

			// The key is stored as the seed form of PKCS#8, named by the hash of the SPKI, and is the one the CSR is for.
			files := keyFiles(t, w)
			sum := sha256.Sum256(csr.RawSubjectPublicKeyInfo)
			if len(files) != 1 || filepath.Base(files[0]) != hex.EncodeToString(sum[:])+".key" {
				t.Fatalf("expected the one key named for the SPKI's hash, got %v", files)
			}
			data, _ := os.ReadFile(files[0])
			seed := seedOf(t, data, alg.oid)
			derived, _ := alg.scheme.DeriveKey(seed)
			if got, _ := derived.MarshalBinary(); !bytes.Equal(got, key.PublicKey.Bytes) {
				t.Fatal("the stored key's seed is not the key the CSR is for")
			}

			// Neither the key nor its seed was sent, nor logged.
			assertKeyNeverSent(t, w, files[0])
			for _, r := range w.stub.Requests() {
				for what, form := range map[string][]byte{"its seed": seed, "its seed in base64": []byte(base64.StdEncoding.EncodeToString(seed)), "its seed in hex": []byte(hex.EncodeToString(seed))} {
					if bytes.Contains(r.Body, form) {
						t.Fatalf("a request to %s contains %s", r.Path, what)
					}
				}
			}
			if strings.Contains(logs.String(), "PRIVATE KEY") {
				t.Fatal("the log holds a key")
			}
		})
	}
}

// seedOf is the seed in an RFC 9881 PKCS#8 PEM: a PrivateKeyInfo under the OID, parameters absent, whose privateKey is
// `[0] IMPLICIT OCTET STRING` holding the 32 bytes, with nothing else in the file.
func seedOf(t *testing.T, keyPEM []byte, oid asn1.ObjectIdentifier) []byte {
	t.Helper()
	block, rest := pem.Decode(keyPEM)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatalf("not one PKCS#8 PEM key: %q", keyPEM)
	}
	var info struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
	}
	if rest, err := asn1.Unmarshal(block.Bytes, &info); err != nil || len(rest) != 0 {
		t.Fatalf("not a PrivateKeyInfo: %v", err)
	}
	if info.Version != 0 || !info.Algorithm.Algorithm.Equal(oid) || !noParameters(info.Algorithm) {
		t.Fatalf("version %d, algorithm %v, parameters %x", info.Version, info.Algorithm.Algorithm, info.Algorithm.Parameters.FullBytes)
	}
	// 0x80 is [0] IMPLICIT, primitive; 0x20 is 32 bytes.
	if len(info.PrivateKey) != 34 || info.PrivateKey[0] != 0x80 || info.PrivateKey[1] != 0x20 {
		t.Fatalf("the private key is not the seed form: %x", info.PrivateKey)
	}
	return info.PrivateKey[2:]
}

// issueFor is a Certificate for the SubjectPublicKeyInfo as the platform's CA would issue it, which copies the CSR's
// SubjectPublicKeyInfo unchanged: Go's X.509 package cannot issue one for an ML-DSA key, so it is built from its parts.
// The Agent reads the Certificate, which it does not verify, so the CA signs with ECDSA.
func (ca *testCA) issueFor(t *testing.T, publicKeyInfo []byte, name string) (leafPEM, chainPEM, fingerprint string) {
	t.Helper()
	type validity struct{ NotBefore, NotAfter time.Time }
	type tbsCertificate struct {
		Version    int `asn1:"explicit,tag:0"`
		Serial     *big.Int
		Algorithm  pkix.AlgorithmIdentifier
		Issuer     asn1.RawValue
		Validity   validity
		Subject    asn1.RawValue
		PublicKey  asn1.RawValue
		Extensions []pkix.Extension `asn1:"explicit,tag:3"`
	}
	ecdsaSHA256 := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}}
	subject, err := asn1.Marshal(pkix.Name{CommonName: name}.ToRDNSequence())
	if err != nil {
		t.Fatal(err)
	}
	names, err := asn1.Marshal([]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte(name)}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	tbs, err := asn1.Marshal(tbsCertificate{
		Version: 2, Serial: big.NewInt(time.Now().UnixNano()), Algorithm: ecdsaSHA256,
		Issuer: asn1.RawValue{FullBytes: ca.cert.RawSubject}, Validity: validity{now.Add(-time.Minute), now.Add(24 * time.Hour)},
		Subject: asn1.RawValue{FullBytes: subject}, PublicKey: asn1.RawValue{FullBytes: publicKeyInfo},
		Extensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: names}},
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(tbs)
	signature, err := ecdsa.SignASN1(rand.Reader, ca.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}{asn1.RawValue{FullBytes: tbs}, ecdsaSHA256, asn1.BitString{Bytes: signature, BitLength: 8 * len(signature)}})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	leaf := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return leaf, leaf + ca.pem, hex.EncodeToString(sum[:])
}

func TestAnMLDSAKeyIsHandedToTheScriptForTheMLDSACertificate(t *testing.T) {
	needBash(t)
	for _, alg := range mlDsaAlgorithms {
		t.Run(alg.name, func(t *testing.T) {
			w, _ := relayWorld(t)
			w.stub.Enqueue(generateKeyItem("k1", alg.name, "app.example.test"))
			w.runUntilReported(1)
			if r := w.stub.Results()[0]; !r.OK {
				t.Fatalf("got %+v", r)
			}
			block, _ := pem.Decode([]byte(w.stub.Results()[0].CSR))
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			ca := newTestCA(t)
			leaf, chain, fingerprint := ca.issueFor(t, csr.RawSubjectPublicKeyInfo, "app.example.test")
			// Go reads the Certificate although it can say nothing of its key.
			if parsed, _ := parseChainLeaf(t, leaf); parsed.PublicKey != nil {
				t.Fatalf("Go gives the ML-DSA key as %T", parsed.PublicKey)
			}

			d := &deployWorld{world: w, leaf: leaf, chain: chain, fingerprint: fingerprint, intermediate: ca.pem, out: filepath.Join(t.TempDir(), "seen")}
			d.stub.Enqueue(d.runItem("r1", fmt.Sprintf("set -eu\ncat \"$CERT_KEY_FILE\" > %q\n", d.out)))
			r := d.result(2)
			if !r.OK || r.Run == nil || r.Run.ExitCode == nil || *r.Run.ExitCode != 0 {
				t.Fatalf("got %+v run %+v", r, r.Run)
			}
			handed, err := os.ReadFile(d.out)
			if err != nil {
				t.Fatal(err)
			}
			stored, _ := os.ReadFile(keyFiles(t, w)[0])
			if !bytes.Equal(handed, stored) {
				t.Fatal("the script was not handed the stored key")
			}
			seedOf(t, handed, alg.oid)
		})
	}
}

func parseChainLeaf(t *testing.T, leafPEM string) (*x509.Certificate, error) {
	t.Helper()
	block, _ := pem.Decode([]byte(leafPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert, nil
}

func TestAnMLDSACertificateForAKeyThisAgentDoesNotHoldIsNotDeployed(t *testing.T) {
	needBash(t)
	w, _ := relayWorld(t)
	w.stub.Enqueue(generateKeyItem("k1", "ml-dsa-65", "app.example.test"))
	w.runUntilReported(1)
	other, _ := mldsa65.NewKeyFromSeed(&[32]byte{1})
	otherKey, err := asn1.Marshal(spki{pkix.AlgorithmIdentifier{Algorithm: mlDsaAlgorithms[1].oid}, asn1.BitString{Bytes: other.Bytes(), BitLength: 8 * len(other.Bytes())}})
	if err != nil {
		t.Fatal(err)
	}
	ca := newTestCA(t)
	leaf, chain, fingerprint := ca.issueFor(t, otherKey, "app.example.test")
	d := &deployWorld{world: w, leaf: leaf, chain: chain, fingerprint: fingerprint, intermediate: ca.pem, out: filepath.Join(t.TempDir(), "seen")}
	d.stub.Enqueue(d.runItem("r1", fmt.Sprintf("touch %q\n", d.out)))
	r := d.result(2)
	if r.OK || r.Run == nil || r.Run.ExitCode != nil || !strings.Contains(r.Run.Output, "key") {
		t.Fatalf("got %+v run %+v", r, r.Run)
	}
	if _, err := os.Stat(d.out); err == nil {
		t.Fatal("the script ran")
	}
}

// A key an Agent made before ML-DSA was named by the hash of its public key as Go encodes it; the Certificate's own
// SubjectPublicKeyInfo is that encoding, so the Agent must go on finding those keys, and new ones are named the same way.
func TestRSAAndECDSAKeysAreFoundByTheNameTheyAlwaysHad(t *testing.T) {
	needBash(t)
	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	for name, key := range map[string]any{"ecdsa-p256": ecdsaKey, "rsa-2048": rsaKey} {
		t.Run(name, func(t *testing.T) {
			var public any
			switch k := key.(type) {
			case *ecdsa.PrivateKey:
				public = &k.PublicKey
			case *rsa.PrivateKey:
				public = &k.PublicKey
			}
			der, _ := x509.MarshalPKCS8PrivateKey(key)
			spkiDER, _ := x509.MarshalPKIXPublicKey(public)
			sum := sha256.Sum256(spkiDER)

			// Stored by an Agent of before.
			w, _ := relayWorld(t)
			dir := filepath.Join(w.cfg.StateDir, "keys", mcID)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(dir, hex.EncodeToString(sum[:])+".key")
			if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
				t.Fatal(err)
			}
			ca := newTestCA(t)
			leaf, chain, fingerprint := ca.issueFor(t, spkiDER, "app.example.test")
			d := &deployWorld{world: w, leaf: leaf, chain: chain, fingerprint: fingerprint, intermediate: ca.pem, out: filepath.Join(t.TempDir(), "seen")}
			d.stub.Enqueue(d.runItem("r1", fmt.Sprintf("set -eu\necho \"$CERT_KEY_FILE\" > %q\n", d.out)))
			r := d.result(1)
			if !r.OK || r.Run == nil || r.Run.ExitCode == nil || *r.Run.ExitCode != 0 {
				t.Fatalf("got %+v run %+v", r, r.Run)
			}
			if seen, _ := os.ReadFile(d.out); strings.TrimSpace(string(seen)) != file {
				t.Fatalf("CERT_KEY_FILE=%q, want %q", seen, file)
			}

			// And a key made now is named the same way.
			w2, _ := relayWorld(t)
			w2.stub.Enqueue(generateKeyItem("k1", name, "app.example.test"))
			w2.runUntilReported(1)
			block, _ := pem.Decode([]byte(w2.stub.Results()[0].CSR))
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			made := sha256.Sum256(csr.RawSubjectPublicKeyInfo)
			again, _ := x509.MarshalPKIXPublicKey(csr.PublicKey)
			if files := keyFiles(t, w2); len(files) != 1 || filepath.Base(files[0]) != hex.EncodeToString(made[:])+".key" || sha256.Sum256(again) != made {
				t.Fatalf("stored %v", files)
			}
		})
	}
}
