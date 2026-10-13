// Seam B for relayed DNS Providers: the Agent is given DNS Provider operations as work items by a stub platform built from
// the contract, carries them out against DNS servers of its own (a TSIG-checking RFC 2136 server and an Infoblox WAPI), and
// reports how each went. The platform's side of this is in server/test/relayed-dns-providers.test.ts.
package agent_test

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"

	"certificate-platform/agent/internal/platformstub"
)

// syncBuffer is what the Agent's log is written to, to see that nothing secret is.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

const (
	tsigSecret = "dGVzdC10c2lnLWtleS1mb3ItdGhlLXJmYzIxMzYtdGVzdHM="
	zone       = "relay.test"
	keyName    = "relay-key"
)

func dnsItem(id, operation string, provider map[string]any, record map[string]any) platformstub.WorkItem {
	payload := map[string]any{"provider": provider}
	if record != nil {
		payload["record"] = record
	}
	return platformstub.WorkItem{ID: id, Type: operation, Payload: payload}
}

func rfc2136Provider(d *dnsDouble, secret string) map[string]any {
	return map[string]any{"type": "rfc2136", "settings": d.settings(), "secret": secret}
}

func txtRecord(name, value string) map[string]any {
	return map[string]any{"name": name, "value": value}
}

// relayWorld is a registered Agent whose log is captured.
func relayWorld(t *testing.T) (*world, *syncBuffer) {
	t.Helper()
	w := newWorld(t, platformstub.Options{})
	logs := &syncBuffer{}
	w.cfg.Log = slog.New(slog.NewTextHandler(logs, nil))
	w.register()
	return w, logs
}

func (w *world) runUntilReported(n int) {
	w.t.Helper()
	if err := w.runUntil(func() bool { return len(w.stub.Results()) >= n }); err != nil {
		w.t.Fatal(err)
	}
}

func TestARelayedRFC2136ProviderPublishesAndRemovesRecordsAndTestsTheConnection(t *testing.T) {
	w, _ := relayWorld(t)
	dnsServer := startDNS(t, zone, keyName, tsigSecret)
	provider := rfc2136Provider(dnsServer, tsigSecret)
	name := "_acme-challenge.app." + zone

	w.stub.Enqueue(dnsItem("a", "dns.present", provider, txtRecord(name, "first")))
	w.stub.Enqueue(dnsItem("b", "dns.present", provider, txtRecord(name+".", "second")))
	w.stub.Enqueue(dnsItem("c", "dns.cleanup", provider, txtRecord(name, "first")))
	w.runUntilReported(3)

	for _, r := range w.stub.Results() {
		if !r.OK {
			t.Fatalf("%s failed: %s", r.ID, r.Error)
		}
	}
	// Each was reported once, in the order given; removing one record left the other, which shared its name.
	if got := dnsServer.txt(name); len(got) != 1 || got[0] != "second" {
		t.Fatalf("the records at %s are %v, want only the one that was not removed", name, got)
	}

	w.stub.Enqueue(dnsItem("d", "dns.test", provider, nil))
	w.runUntilReported(4)
	if r := w.stub.Results()[3]; !r.OK {
		t.Fatalf("the connection test failed: %s", r.Error)
	}
	if n := dnsServer.allRecords(); n != 1 {
		t.Fatalf("the test left %d records, want only the one published before it", n)
	}
}

func TestAnUpdateOutsideTheZoneIsRefusedWithoutReachingTheServer(t *testing.T) {
	w, _ := relayWorld(t)
	dnsServer := startDNS(t, zone, keyName, tsigSecret)
	w.stub.Enqueue(dnsItem("a", "dns.present", rfc2136Provider(dnsServer, tsigSecret), txtRecord("_acme-challenge.elsewhere.test", "v")))
	w.runUntilReported(1)
	r := w.stub.Results()[0]
	if r.OK || r.Kind != "rejected" || !strings.Contains(r.Error, "not inside the zone "+zone) {
		t.Fatalf("got %+v", r)
	}
	if dnsServer.updates != 0 {
		t.Fatalf("the server was asked %d times", dnsServer.updates)
	}
}

func TestADNSServerThatRefusesTheKeyIsReportedAsRejectedWithoutTheSecret(t *testing.T) {
	cases := map[string]struct {
		provider func(*dnsDouble) map[string]any
		want     string
	}{
		"wrong secret": {func(d *dnsDouble) map[string]any {
			return rfc2136Provider(d, "bm90LXRoZS1zZXJ2ZXJzLWtleS1hdC1hbGw=")
		}, "BADSIG"},
		"unknown key": {func(d *dnsDouble) map[string]any {
			p := rfc2136Provider(d, tsigSecret)
			p["settings"].(map[string]any)["keyName"] = "other-key"
			return p
		}, "BADKEY"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			w, logs := relayWorld(t)
			dnsServer := startDNS(t, zone, keyName, tsigSecret)
			provider := c.provider(dnsServer)
			w.stub.Enqueue(dnsItem("a", "dns.present", provider, txtRecord("_acme-challenge."+zone, "v")))
			w.runUntilReported(1)

			r := w.stub.Results()[0]
			if r.OK || r.Kind != "rejected" || !strings.Contains(r.Error, c.want) {
				t.Fatalf("got %+v, want a rejection saying %s", r, c.want)
			}
			if dnsServer.allRecords() != 0 {
				t.Fatal("a record was published with a signature the server does not accept")
			}
			assertNoSecret(t, w, logs, provider["secret"].(string))
		})
	}
}

func TestADNSServerThatDoesNotAnswerIsReportedAsUnreachable(t *testing.T) {
	w, _ := relayWorld(t)
	dnsServer := startDNS(t, zone, keyName, tsigSecret)
	provider := rfc2136Provider(dnsServer, tsigSecret)
	provider["settings"].(map[string]any)["port"] = 1 // nothing listens there
	w.stub.Enqueue(dnsItem("a", "dns.test", provider, nil))
	w.runUntilReported(1)
	r := w.stub.Results()[0]
	if r.OK || r.Kind != "unreachable" || !strings.Contains(r.Error, "could not be reached") {
		t.Fatalf("got %+v", r)
	}
}

func TestARelayedInfobloxProviderPublishesAndRemovesRecordsThroughTheWAPI(t *testing.T) {
	w, _ := relayWorld(t)
	wapi := startWAPI(t, zone, "wapi-user", "wapi-password")
	provider := map[string]any{"type": "infoblox", "settings": wapi.settings(), "secret": wapi.credentials()}
	name := "_acme-challenge.app." + zone

	w.stub.Enqueue(dnsItem("a", "dns.present", provider, txtRecord(name, "first")))
	w.stub.Enqueue(dnsItem("b", "dns.present", provider, txtRecord(name, "second")))
	w.stub.Enqueue(dnsItem("c", "dns.present", provider, txtRecord(name, "second"))) // again: already there
	w.stub.Enqueue(dnsItem("d", "dns.cleanup", provider, txtRecord(name, "first")))
	w.stub.Enqueue(dnsItem("e", "dns.cleanup", provider, txtRecord(name, "never-was"))) // already gone is a success
	w.runUntilReported(5)
	for _, r := range w.stub.Results() {
		if !r.OK {
			t.Fatalf("%s failed: %s", r.ID, r.Error)
		}
	}
	if got := wapi.texts(name); len(got) != 1 || got[0] != "second" {
		t.Fatalf("the records at %s are %v", name, got)
	}

	w.stub.Enqueue(dnsItem("f", "dns.test", provider, nil))
	w.runUntilReported(6)
	if r := w.stub.Results()[5]; !r.OK {
		t.Fatalf("the connection test failed: %s", r.Error)
	}
	if got := wapi.texts("_acme-challenge." + zone); len(got) != 0 {
		t.Fatalf("the test left %v", got)
	}
}

func TestAnInfobloxProviderWithWrongCredentialsIsReportedAsRejectedWithoutThem(t *testing.T) {
	w, logs := relayWorld(t)
	wapi := startWAPI(t, zone, "wapi-user", "wapi-password")
	provider := map[string]any{"type": "infoblox", "settings": wapi.settings(), "secret": "wapi-user:not-the-password"}
	w.stub.Enqueue(dnsItem("a", "dns.test", provider, nil))
	w.runUntilReported(1)
	r := w.stub.Results()[0]
	if r.OK || r.Kind != "rejected" || !strings.Contains(r.Error, "credentials") {
		t.Fatalf("got %+v", r)
	}
	assertNoSecret(t, w, logs, "not-the-password")
}

func TestAWorkItemTheAgentCannotCarryOutFailsAloneAndTheNextIsStillDone(t *testing.T) {
	w, _ := relayWorld(t)
	dnsServer := startDNS(t, zone, keyName, tsigSecret)
	name := "_acme-challenge." + zone
	w.stub.Enqueue(dnsItem("a", "dns.present", map[string]any{"type": "route53", "settings": map[string]any{}, "secret": "s"}, txtRecord(name, "v")))
	w.stub.Enqueue(dnsItem("b", "dns.present", map[string]any{"type": "rfc2136", "settings": map[string]any{"server": ""}, "secret": "s"}, txtRecord(name, "v")))
	w.stub.Enqueue(dnsItem("c", "dns.present", rfc2136Provider(dnsServer, tsigSecret), txtRecord(name, "v")))
	w.runUntilReported(3)

	results := w.stub.Results()
	if results[0].OK || results[0].Kind != "rejected" || !strings.Contains(results[0].Error, "route53") {
		t.Fatalf("an unknown type of provider: %+v", results[0])
	}
	if results[1].OK || results[1].Kind != "rejected" {
		t.Fatalf("settings that are not a provider's: %+v", results[1])
	}
	if !results[2].OK {
		t.Fatalf("the item after them failed too: %+v", results[2])
	}
}

func TestAWorkItemOfATypeTheAgentDoesNotKnowIsIgnoredAndNotReported(t *testing.T) {
	w, _ := relayWorld(t)
	dnsServer := startDNS(t, zone, keyName, tsigSecret)
	w.stub.Enqueue(platformstub.WorkItem{ID: "x", Type: "keys.generate", Payload: map[string]any{}})
	w.stub.Enqueue(dnsItem("a", "dns.test", rfc2136Provider(dnsServer, tsigSecret), nil))
	w.runUntilReported(1)
	if results := w.stub.Results(); len(results) != 1 || results[0].ID != "a" {
		t.Fatalf("got %+v", results)
	}
}

func TestTheProvidersSecretIsNeverSentBackLoggedOrKept(t *testing.T) {
	w, logs := relayWorld(t)
	dnsServer := startDNS(t, zone, keyName, tsigSecret)
	w.stub.Enqueue(dnsItem("a", "dns.present", rfc2136Provider(dnsServer, tsigSecret), txtRecord("_acme-challenge."+zone, "v")))
	w.runUntilReported(1)
	assertNoSecret(t, w, logs, tsigSecret)
	// Nor is it kept: the state directory holds the credential and nothing else.
	entries, err := readDir(w.cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e != "credential.json" {
			t.Fatalf("the Agent keeps %s", e)
		}
	}
}

// assertNoSecret fails if the secret is in anything the Agent said to the platform (apart from the polls that it received it in) or logged.
func assertNoSecret(t *testing.T, w *world, logs *syncBuffer, secret string) {
	t.Helper()
	for _, r := range w.stub.Requests() {
		if bytes.Contains(r.Body, []byte(secret)) {
			t.Fatalf("a request to %s contains the secret", r.Path)
		}
	}
	if strings.Contains(logs.String(), secret) {
		t.Fatalf("the Agent's log contains the secret: %s", logs.String())
	}
}

var _ = context.Background

func readDir(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, err
}
