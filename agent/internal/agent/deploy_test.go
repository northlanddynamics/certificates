// Seam B for Deployments: the Agent is given work items by a stub platform built from the contract. It makes keys locally
// and reports only CSRs (ADR 0002), and runs a Deployment Script only if its content matches the hash it was given
// (ADR 0004), with the Certificate's files and the Managed Certificate's identifiers in its environment. The platform's
// side of this is in server/test/first-deployment.test.ts.
package agent_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"certificate-platform/agent/internal/platformstub"
)

const mcID = "11111111-2222-4333-8444-555555555555"

func generateKeyItem(id string, algorithm string, names ...string) platformstub.WorkItem {
	return platformstub.WorkItem{ID: id, Type: "deployment.generate_key", Payload: map[string]any{
		"deploymentId": "d0000000-0000-4000-8000-000000000001", "managedCertificateId": mcID, "names": names, "keyAlgorithm": algorithm,
	}}
}

// keyFiles are the private keys the Agent stored for the Managed Certificate.
func keyFiles(t *testing.T, w *world) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(w.cfg.StateDir, "keys", mcID, "*"))
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func parseCSR(t *testing.T, csrPEM string) *x509.CertificateRequest {
	t.Helper()
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		t.Fatalf("not a PEM CSR: %q", csrPEM)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		t.Fatalf("the CSR is not good: %v", err)
	}
	return csr
}

// assertKeyNeverSent fails if any request body holds the key in the file, in any form a body could carry it.
func assertKeyNeverSent(t *testing.T, w *world, keyFile string) {
	t.Helper()
	data, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("%s is not a PEM key", keyFile)
	}
	forms := map[string]string{
		"its base64": base64.StdEncoding.EncodeToString(block.Bytes),
		"its PEM":    strings.TrimSpace(string(data)),
		"a PEM key":  "PRIVATE KEY",
		"its hex":    hex.EncodeToString(block.Bytes),
	}
	for _, r := range w.stub.Requests() {
		for what, form := range forms {
			if bytes.Contains(r.Body, []byte(form)) {
				t.Fatalf("a request to %s contains %s", r.Path, what)
			}
		}
	}
}

func TestTheAgentMakesTheKeyItselfAndSendsOnlyACSRForIt(t *testing.T) {
	algorithms := map[string]func(*testing.T, any){
		"ecdsa-p256": func(t *testing.T, pub any) {
			if k, ok := pub.(*ecdsa.PublicKey); !ok || k.Curve != elliptic.P256() {
				t.Fatalf("not a P-256 key: %T", pub)
			}
		},
		"ecdsa-p384": func(t *testing.T, pub any) {
			if k, ok := pub.(*ecdsa.PublicKey); !ok || k.Curve != elliptic.P384() {
				t.Fatalf("not a P-384 key: %T", pub)
			}
		},
		"rsa-2048": func(t *testing.T, pub any) { assertRSA(t, pub, 2048) },
		"rsa-3072": func(t *testing.T, pub any) { assertRSA(t, pub, 3072) },
		"rsa-4096": func(t *testing.T, pub any) { assertRSA(t, pub, 4096) },
	}
	for algorithm, check := range algorithms {
		t.Run(algorithm, func(t *testing.T) {
			w, logs := relayWorld(t)
			w.stub.Enqueue(generateKeyItem("k1", algorithm, "app.example.test", "*.wild.example.test"))
			w.runUntilReported(1)

			r := w.stub.Results()[0]
			if !r.OK || r.CSR == "" || r.Run != nil {
				t.Fatalf("got %+v", r)
			}
			csr := parseCSR(t, r.CSR)
			check(t, csr.PublicKey)
			if got := strings.Join(csr.DNSNames, ","); got != "app.example.test,*.wild.example.test" {
				t.Fatalf("the CSR asks for %s", got)
			}

			// The key is stored, is the one the CSR is for, and was sent nowhere.
			files := keyFiles(t, w)
			if len(files) != 1 {
				t.Fatalf("expected one stored key, got %v", files)
			}
			data, _ := os.ReadFile(files[0])
			block, _ := pem.Decode(data)
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			der, _ := x509.MarshalPKIXPublicKey(key.(crypto.Signer).Public())
			if !bytes.Equal(der, csr.RawSubjectPublicKeyInfo) {
				t.Fatal("the stored key is not the one the CSR is for")
			}
			assertKeyNeverSent(t, w, files[0])
			if strings.Contains(logs.String(), "PRIVATE KEY") {
				t.Fatal("the log holds a key")
			}
		})
	}
}

func assertRSA(t *testing.T, pub any, bits int) {
	t.Helper()
	if k, ok := pub.(*rsa.PublicKey); !ok || k.N.BitLen() != bits {
		t.Fatalf("not an RSA-%d key: %T", bits, pub)
	}
}

func TestKeysAreKeptForTheServiceAccountAlone(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes do not protect files on Windows; the installer sets the directory's ACL")
	}
	for _, algorithm := range []string{"ecdsa-p256", "ml-dsa-44"} {
		t.Run(algorithm, func(t *testing.T) {
			w, _ := relayWorld(t)
			w.stub.Enqueue(generateKeyItem("k1", algorithm, "app.example.test"))
			w.runUntilReported(1)
			files := keyFiles(t, w)
			if len(files) != 1 {
				t.Fatalf("expected one stored key, got %v", files)
			}
			for path, want := range map[string]os.FileMode{
				filepath.Join(w.cfg.StateDir, "keys"):       0o700,
				filepath.Join(w.cfg.StateDir, "keys", mcID): 0o700,
				files[0]: 0o600,
			} {
				info, err := os.Stat(path)
				if err != nil || info.Mode().Perm() != want {
					t.Fatalf("%s: mode %v, %v; want %v", path, info.Mode().Perm(), err, want)
				}
			}
		})
	}
}

func TestAKeyThatCannotBeMadeIsReportedAndNothingIsStored(t *testing.T) {
	cases := map[string]platformstub.WorkItem{
		"an algorithm it does not know":        generateKeyItem("a", "dsa-1024", "app.example.test"),
		"an ML-DSA algorithm it does not know": generateKeyItem("d", "ml-dsa-99", "app.example.test"),
		"no names":                             generateKeyItem("b", "ecdsa-p256"),
		"a Managed Certificate id with a dot":  {ID: "c", Type: "deployment.generate_key", Payload: map[string]any{"deploymentId": "d", "managedCertificateId": "../../escape", "names": []string{"a.example.test"}, "keyAlgorithm": "ecdsa-p256"}},
	}
	for name, item := range cases {
		t.Run(name, func(t *testing.T) {
			w, _ := relayWorld(t)
			w.stub.Enqueue(item)
			w.runUntilReported(1)
			r := w.stub.Results()[0]
			if r.OK || r.CSR != "" || r.Error == "" {
				t.Fatalf("got %+v", r)
			}
			if _, err := os.Stat(filepath.Join(w.cfg.StateDir, "keys")); err == nil {
				if entries, _ := os.ReadDir(filepath.Join(w.cfg.StateDir, "keys")); len(entries) > 0 {
					t.Fatalf("something was stored: %v", entries)
				}
			}
		})
	}
}

// ---- Running the script ---------------------------------------------------------------------------------------------

// testCA issues the leaf Certificates the platform would.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test intermediate"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert: cert, key: key, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

// issue is a Certificate for the CSR: the leaf, then the intermediate, as the platform stores a chain.
func (ca *testCA) issue(t *testing.T, csr *x509.CertificateRequest) (leafPEM, chainPEM, fingerprint string) {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: csr.DNSNames[0]}, DNSNames: csr.DNSNames,
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	leaf := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return leaf, leaf + ca.pem, hex.EncodeToString(sum[:])
}

func needBash(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("these tests run Bash scripts")
	}
}

func hashOf(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// deployWorld is an Agent that has made the key for the Managed Certificate, with the Certificate the platform issued for its CSR.
type deployWorld struct {
	*world
	leaf, chain, fingerprint string
	intermediate             string
	out                      string
}

func newDeployWorld(t *testing.T) *deployWorld {
	t.Helper()
	needBash(t)
	w, _ := relayWorld(t)
	w.stub.Enqueue(generateKeyItem("k1", "ecdsa-p256", "app.example.test"))
	w.runUntilReported(1)
	ca := newTestCA(t)
	leaf, chain, fingerprint := ca.issue(t, parseCSR(t, w.stub.Results()[0].CSR))
	return &deployWorld{world: w, leaf: leaf, chain: chain, fingerprint: fingerprint, intermediate: ca.pem, out: filepath.Join(t.TempDir(), "seen")}
}

func (d *deployWorld) runItem(id, content string, mutate ...func(map[string]any)) platformstub.WorkItem {
	payload := map[string]any{
		"deploymentId": "d0000000-0000-4000-8000-000000000001", "managedCertificateId": mcID, "trigger": "issuance",
		"names":       []string{"app.example.test"},
		"certificate": map[string]any{"id": "c0000000-0000-4000-8000-000000000001", "fingerprint": d.fingerprint, "notAfter": time.Now().Add(time.Hour).Format(time.RFC3339), "chainPem": d.chain},
		"script":      map[string]any{"name": "install", "interpreter": "bash", "version": 1, "hash": hashOf(content), "content": content},
	}
	for _, m := range mutate {
		m(payload)
	}
	return platformstub.WorkItem{ID: id, Type: "deployment.run", Payload: payload}
}

func (d *deployWorld) result(n int) platformstub.Result {
	d.t.Helper()
	d.runUntilReported(n)
	return d.stub.Results()[n-1]
}

func TestTheScriptRunsWithTheCertificateFilesAndIdentifiersInItsEnvironment(t *testing.T) {
	d := newDeployWorld(t)
	script := fmt.Sprintf("#!/usr/bin/env bash\nset -eu\n{\nfor v in CERT_KEY_FILE CERT_LEAF_FILE CERT_CHAIN_FILE CERT_FULLCHAIN_FILE CERT_MANAGED_CERTIFICATE_ID CERT_DEPLOYMENT_ID CERT_FINGERPRINT CERT_NAMES CERT_NOT_AFTER; do echo \"$v=${!v}\"; done\n} > %q\necho deployed\necho warning >&2\n", d.out)
	d.stub.Enqueue(d.runItem("r1", script))
	r := d.result(2)

	if !r.OK || r.Run == nil || r.Run.ExitCode == nil || *r.Run.ExitCode != 0 {
		t.Fatalf("got %+v run %+v", r, r.Run)
	}
	if !strings.Contains(r.Run.Output, "deployed") || !strings.Contains(r.Run.Output, "warning") || r.Run.OutputTruncated {
		t.Fatalf("output %q truncated %v", r.Run.Output, r.Run.OutputTruncated)
	}
	started, err1 := time.Parse(time.RFC3339, r.Run.StartedAt)
	finished, err2 := time.Parse(time.RFC3339, r.Run.FinishedAt)
	if err1 != nil || err2 != nil || finished.Before(started) {
		t.Fatalf("times %q %q", r.Run.StartedAt, r.Run.FinishedAt)
	}

	seen := map[string]string{}
	data, err := os.ReadFile(d.out)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		k, v, _ := strings.Cut(line, "=")
		seen[k] = v
	}
	for k, want := range map[string]string{
		"CERT_MANAGED_CERTIFICATE_ID": mcID, "CERT_DEPLOYMENT_ID": "d0000000-0000-4000-8000-000000000001",
		"CERT_FINGERPRINT": d.fingerprint, "CERT_NAMES": "app.example.test",
	} {
		if seen[k] != want {
			t.Fatalf("%s=%q, want %q", k, seen[k], want)
		}
	}
	read := func(name string) string {
		b, err := os.ReadFile(seen[name])
		if err != nil {
			t.Fatalf("%s (%q): %v", name, seen[name], err)
		}
		return string(b)
	}
	if read("CERT_LEAF_FILE") != d.leaf || read("CERT_CHAIN_FILE") != d.intermediate || read("CERT_FULLCHAIN_FILE") != d.chain {
		t.Fatal("the leaf, chain and full-chain files are not the Certificate's")
	}
	// The key path is the stored key, which is for the Certificate.
	if files := keyFiles(t, d.world); len(files) != 1 || seen["CERT_KEY_FILE"] != files[0] {
		t.Fatalf("CERT_KEY_FILE=%q, stored keys %v", seen["CERT_KEY_FILE"], files)
	}
	if !strings.Contains(read("CERT_KEY_FILE"), "PRIVATE KEY") {
		t.Fatal("the key file holds no key")
	}
	// Nothing the platform was sent holds the key.
	assertKeyNeverSent(t, d.world, seen["CERT_KEY_FILE"])
}

func TestAScriptThatExitsNonZeroIsReportedAsFailedWithItsExitCodeAndOutput(t *testing.T) {
	d := newDeployWorld(t)
	d.stub.Enqueue(d.runItem("r1", "echo copying\necho 'no space left' >&2\nexit 7\n"))
	r := d.result(2)
	if r.OK || r.Run == nil || r.Run.ExitCode == nil || *r.Run.ExitCode != 7 || !strings.Contains(r.Run.Output, "no space left") || r.Error == "" {
		t.Fatalf("got %+v run %+v", r, r.Run)
	}
}

func TestAScriptThatDoesNotMatchItsHashIsNotRun(t *testing.T) {
	d := newDeployWorld(t)
	content := fmt.Sprintf("touch %q\n", d.out)
	d.stub.Enqueue(d.runItem("r1", content, func(p map[string]any) { p["script"].(map[string]any)["hash"] = hashOf(content + "# something else\n") }))
	r := d.result(2)
	if r.OK || r.Run == nil || r.Run.ExitCode != nil || !strings.Contains(r.Run.Output, "hash") {
		t.Fatalf("got %+v run %+v", r, r.Run)
	}
	if _, err := os.Stat(d.out); err == nil {
		t.Fatal("the script ran although it did not match its hash")
	}
}

func TestACertificateThatIsNotTheOneNamedOrHasNoKeyHereIsNotDeployed(t *testing.T) {
	cases := map[string]func(*deployWorld) func(map[string]any){
		"a leaf that is not the Certificate named": func(*deployWorld) func(map[string]any) {
			return func(p map[string]any) { p["certificate"].(map[string]any)["fingerprint"] = strings.Repeat("0", 64) }
		},
		"a Certificate for a key this Agent does not hold": func(d *deployWorld) func(map[string]any) {
			ca := newTestCA(t)
			key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x.test"}, DNSNames: []string{"x.test"}}, key)
			csr, _ := x509.ParseCertificateRequest(der)
			_, chain, fp := ca.issue(t, csr)
			return func(p map[string]any) {
				c := p["certificate"].(map[string]any)
				c["chainPem"], c["fingerprint"] = chain, fp
			}
		},
	}
	for name, mutation := range cases {
		t.Run(name, func(t *testing.T) {
			d := newDeployWorld(t)
			content := fmt.Sprintf("touch %q\n", d.out)
			d.stub.Enqueue(d.runItem("r1", content, mutation(d)))
			r := d.result(2)
			if r.OK || r.Run == nil || r.Run.ExitCode != nil || r.Run.Output == "" {
				t.Fatalf("got %+v run %+v", r, r.Run)
			}
			if _, err := os.Stat(d.out); err == nil {
				t.Fatal("the script ran")
			}
		})
	}
}

func TestOutputIsReportedUpToALimit(t *testing.T) {
	d := newDeployWorld(t)
	d.stub.Enqueue(d.runItem("r1", "head -c 200000 /dev/zero | tr '\\0' 'x'\necho\n"))
	r := d.result(2)
	if !r.OK || r.Run == nil || len(r.Run.Output) > 32*1024 || len(r.Run.Output) < 32*1024-4 || !r.Run.OutputTruncated {
		t.Fatalf("ok %v output %d bytes truncated %v", r.OK, len(r.Run.Output), r.Run.OutputTruncated)
	}
}

func TestAScriptThatNeverEndsIsStoppedAndReported(t *testing.T) {
	d := newDeployWorld(t)
	d.cfg.ScriptTimeout = time.Second
	d.stub.Enqueue(d.runItem("r1", "echo started\nsleep 60\n"))
	start := time.Now()
	r := d.result(2)
	if r.OK || r.Run == nil || !strings.Contains(r.Run.Output, "started") || !strings.Contains(r.Run.Output, "stopped") {
		t.Fatalf("got %+v run %+v", r, r.Run)
	}
	if time.Since(start) > 20*time.Second {
		t.Fatal("the script was not stopped")
	}
}

func withParameters(values map[string]any) func(map[string]any) {
	return func(p map[string]any) { p["parameters"] = values }
}

func TestTheScriptIsGivenEachParameterUnderThePrefixOverAnyAgentVariableAndAnUnsetOneIsAbsent(t *testing.T) {
	d := newDeployWorld(t)
	t.Setenv("DEPLOY_PARAM_SITE_ID", "from the Agent")
	t.Setenv("DEPLOY_PARAM_PORT", "from the Agent")
	script := fmt.Sprintf("#!/usr/bin/env bash\nset -eu\n{\necho \"SITE_ID=$DEPLOY_PARAM_SITE_ID\"\necho \"REGION=$DEPLOY_PARAM_REGION\"\necho \"PARAM_PATH=$DEPLOY_PARAM_PATH\"\necho \"PORT=${DEPLOY_PARAM_PORT-absent}\"\necho \"PATH=$PATH\"\n} > %q\n", d.out)
	d.stub.Enqueue(d.runItem("r1", script, withParameters(map[string]any{"SITE_ID": "site-42", "REGION": "eu west 1", "PATH": "/nowhere"})))
	r := d.result(2)
	if !r.OK || r.Run == nil {
		t.Fatalf("got %+v run %+v", r, r.Run)
	}
	data, err := os.ReadFile(d.out)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		k, v, _ := strings.Cut(line, "=")
		seen[k] = v
	}
	// The platform's value wins over the Agent's own variable of the same name, the Agent's own is not passed on for a
	// parameter the work item leaves unset, and a parameter named like an Agent variable does not reach that variable.
	for k, want := range map[string]string{"SITE_ID": "site-42", "REGION": "eu west 1", "PARAM_PATH": "/nowhere", "PORT": "absent", "PATH": os.Getenv("PATH")} {
		if seen[k] != want {
			t.Fatalf("%s=%q, want %q", k, seen[k], want)
		}
	}
}

func TestAParameterWhoseNameIsNotAllowedFailsTheRunAndTheScriptIsNotRun(t *testing.T) {
	for _, name := range []string{"site_id", "1SITE", "_SITE", "", "SITE ID", "X=PATH", "=LD_PRELOAD", "SITE\nLD_PRELOAD", "SITÉ"} {
		t.Run(fmt.Sprintf("%q", name), func(t *testing.T) {
			d := newDeployWorld(t)
			content := fmt.Sprintf("touch %q\n", d.out)
			d.stub.Enqueue(d.runItem("r1", content, withParameters(map[string]any{"SITE_ID": "site-42", name: "/tmp/x"})))
			r := d.result(2)
			if r.OK || r.Error == "" || r.Run == nil || r.Run.ExitCode != nil || !strings.Contains(r.Run.Output, "parameter") {
				t.Fatalf("got %+v run %+v", r, r.Run)
			}
			if _, err := os.Stat(d.out); err == nil {
				t.Fatal("the script ran")
			}
		})
	}
}

func TestAScriptWithNoParametersSeesNoneOfThem(t *testing.T) {
	d := newDeployWorld(t)
	t.Setenv("DEPLOY_PARAM_SITE_ID", "from the Agent")
	script := fmt.Sprintf("#!/usr/bin/env bash\nset -eu\nenv | grep '^DEPLOY_PARAM_' > %q || true\n", d.out)
	for i, mutate := range []func(map[string]any){func(map[string]any) {}, withParameters(map[string]any{})} {
		d.stub.Enqueue(d.runItem(fmt.Sprintf("r%d", i+1), script, mutate))
		r := d.result(i + 2)
		if !r.OK {
			t.Fatalf("got %+v run %+v", r, r.Run)
		}
		if data, err := os.ReadFile(d.out); err != nil || len(data) != 0 {
			t.Fatalf("the script saw %q (%v)", data, err)
		}
	}
}
