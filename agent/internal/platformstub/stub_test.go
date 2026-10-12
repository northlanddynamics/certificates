package platformstub_test

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"strings"
	"testing"
	"time"

	"certificate-platform/agent/internal/platformstub"
)

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// The stub is only worth running the Agent against if it holds the Agent to the contract: a request that does not
// conform must be answered 400 and recorded, so the Agent's tests fail on it.
func TestTheStubRefusesAndRecordsWhatTheContractDoesNotAllow(t *testing.T) {
	stub, err := platformstub.Start(platformstub.Options{Clock: realClock{}})
	if err != nil {
		t.Fatal(err)
	}
	defer stub.Close()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(stub.ServerCertificatePEM())
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}

	for name, body := range map[string]string{
		"missing fields": `{}`,
		"wrong type":     `{"token":1,"csr":"x","hostName":"h","os":"linux","arch":"amd64","version":"1"}`,
		"outside enum":   `{"token":"t","csr":"x","hostName":"h","os":"darwin","arch":"amd64","version":"1"}`,
		"not JSON":       `nope`,
	} {
		before := len(stub.ContractViolations())
		res, err := client.Post(stub.URL()+"/api/agent/registration", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 400 || len(stub.ContractViolations()) != before+1 {
			t.Fatalf("%s: answered %d with %d new violations", name, res.StatusCode, len(stub.ContractViolations())-before)
		}
	}

	// Nor does it serve a route the contract lacks.
	res, err := client.Post(stub.URL()+"/api/agent/unheard-of", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 404 {
		t.Fatalf("answered %d", res.StatusCode)
	}
}

// The routes that need the Agent's identity are the ones the contract marks as secured; without a certificate they are refused.
func TestTheStubTakesWhichRoutesNeedAnIdentityFromTheContract(t *testing.T) {
	stub, err := platformstub.Start(platformstub.Options{Clock: realClock{}})
	if err != nil {
		t.Fatal(err)
	}
	defer stub.Close()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(stub.ServerCertificatePEM())
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	for _, path := range []string{"/api/agent/poll", "/api/agent/identity"} {
		body := `{"version":"1"}`
		if strings.HasSuffix(path, "identity") {
			body = `{"csr":"x"}`
		}
		res, err := client.Post(stub.URL()+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 401 {
			t.Fatalf("%s without a certificate answered %d", path, res.StatusCode)
		}
	}
	if v := stub.ContractViolations(); len(v) != 0 {
		t.Fatalf("%v", v)
	}
}
