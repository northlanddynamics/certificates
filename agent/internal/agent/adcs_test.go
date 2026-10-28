// Seam B for ADCS CAs: the Agent is given `adcs.discover` by a stub platform built from the contract, reaches ADCS through
// the fake ADCS client as it would through MS-WCCE, and reports what it found in the contract's shape. The platform's side of
// this is in server/test/adcs-cas.test.ts.
package agent_test

import (
	"crypto/x509"
	"encoding/pem"
	"runtime"
	"strings"
	"testing"

	"certificate-platform/agent/internal/adcs"
	"certificate-platform/agent/internal/platformstub"
)

const configString = `ca01.corp.example\Corp Issuing CA`

// adcsWorld is a registered Agent that reaches the fake ADCS, with its log captured.
func adcsWorld(t *testing.T) (*world, *adcs.Fake, *syncBuffer) {
	t.Helper()
	fake, err := adcs.NewFake(configString)
	if err != nil {
		t.Fatal(err)
	}
	w, logs := relayWorld(t)
	w.cfg.ADCS = fake
	return w, fake, logs
}

func discoverItem(id, configString string) platformstub.WorkItem {
	return platformstub.WorkItem{ID: id, Type: "adcs.discover", Payload: map[string]any{"configString": configString}}
}

func TestDiscoveryReportsTheChainAndTheTemplatesWithTheirFacts(t *testing.T) {
	w, _, logs := adcsWorld(t)
	w.stub.Enqueue(discoverItem("a", configString))
	w.runUntilReported(1)

	r := w.stub.Results()[0]
	if !r.OK || r.Discovery == nil {
		t.Fatalf("got %+v", r)
	}
	chain := r.Discovery["chain"].([]any)
	if len(chain) != 2 {
		t.Fatalf("the chain has %d certificates, want the CA's and its root's", len(chain))
	}
	block, _ := pem.Decode([]byte(chain[0].(string)))
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil || ca.Subject.CommonName != "Corp Issuing CA" || len(ca.CRLDistributionPoints) != 1 || ca.CRLDistributionPoints[0] != adcs.CDPURL {
		t.Fatalf("the first certificate is not the CA's: %v %+v", err, ca)
	}
	templates := r.Discovery["templates"].([]any)
	if len(templates) != 3 {
		t.Fatalf("%d templates", len(templates))
	}
	web := templates[0].(map[string]any)
	want := map[string]any{
		"name": "CorpWebServer", "oid": "1.3.6.1.4.1.311.21.8.1.1", "displayName": "Corp Web Server", "validityDays": float64(365), "minimumKeySize": float64(2048),
		"managerApproval": false, "subjectFromRequest": true, "enrollable": true, "published": true,
	}
	for key, value := range want {
		if web[key] != value {
			t.Fatalf("%s is %v, want %v", key, web[key], value)
		}
	}
	if ekus := web["extendedKeyUsages"].([]any); len(ekus) != 1 || ekus[0] != "1.3.6.1.5.5.7.3.1" {
		t.Fatalf("EKUs %v", ekus)
	}
	if algorithms := web["keyAlgorithms"].([]any); len(algorithms) != 2 || algorithms[0] != "rsa" || algorithms[1] != "ecdsa-p256" {
		t.Fatalf("key algorithms %v", algorithms)
	}
	if directory := templates[2].(map[string]any); directory["subjectFromRequest"] != false {
		t.Fatalf("%v should build its subject from Active Directory", directory)
	}
	assertNothingSecretLogged(t, w, logs)
}

func TestACAThatIsNotThereIsRejectedAndAHostThatDoesNotAnswerIsUnreachable(t *testing.T) {
	w, fake, logs := adcsWorld(t)
	w.stub.Enqueue(discoverItem("a", `ca01.corp.example\No Such CA`))
	w.stub.Enqueue(discoverItem("b", `ca99.corp.example\Corp Issuing CA`))
	w.runUntilReported(2)
	fake.Fail(adcs.Refused("access is denied"))
	w.stub.Enqueue(discoverItem("c", configString))
	w.stub.Enqueue(discoverItem("d", ""))
	w.runUntilReported(4)

	results := w.stub.Results()
	for i, want := range []struct{ kind, error string }{
		{"rejected", "has no CA named No Such CA"},
		{"unreachable", "the RPC server is unavailable at ca99.corp.example"},
		{"rejected", "access is denied"},
		{"rejected", "does not name an ADCS CA"},
	} {
		if r := results[i]; r.OK || r.Kind != want.kind || !strings.Contains(r.Error, want.error) || r.Discovery != nil {
			t.Fatalf("result %d: got %+v, want %s saying %q", i, r, want.kind, want.error)
		}
	}
	assertNothingSecretLogged(t, w, logs)
}

func TestAnAgentOffWindowsCannotReachADCSAndSaysSo(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the refusal is for an Agent off Windows")
	}
	w, logs := relayWorld(t)
	w.stub.Enqueue(discoverItem("a", configString))
	w.runUntilReported(1)
	r := w.stub.Results()[0]
	if r.OK || r.Kind != "rejected" || r.Error != "this Agent cannot reach ADCS: it does not run on Windows" {
		t.Fatalf("got %+v", r)
	}
	assertNothingSecretLogged(t, w, logs)
}

// assertNothingSecretLogged checks that the Agent's credential and the certificates it reported are not in its log.
func assertNothingSecretLogged(t *testing.T, w *world, logs *syncBuffer) {
	t.Helper()
	assertNoSecret(t, w, logs, w.loadRecord().Credential)
	if strings.Contains(logs.String(), "CERTIFICATE") {
		t.Fatalf("the Agent's log holds a certificate: %s", logs.String())
	}
}
