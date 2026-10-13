package agent_test

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// dnsDouble is a DNS server that takes dynamic updates (RFC 2136) signed with a TSIG key, as BIND does for the platform's
// tests: it keeps the TXT records it is told to, and answers what a real one does to a signature it does not accept.
type dnsDouble struct {
	t       *testing.T
	host    string
	port    int
	zone    string
	keyName string
	secret  string

	mu      sync.Mutex
	records map[string][]string
	updates int
}

func startDNS(t *testing.T, zone, keyName, secret string) *dnsDouble {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d := &dnsDouble{t: t, host: "127.0.0.1", port: listener.Addr().(*net.TCPAddr).Port, zone: zone, keyName: keyName, secret: secret, records: map[string][]string{}}
	server := &dns.Server{Listener: listener, Handler: d, TsigSecret: map[string]string{dns.Fqdn(keyName): secret}, MsgAcceptFunc: acceptUpdates}
	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }
	go func() { _ = server.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = server.Shutdown() })
	return d
}

// acceptUpdates is miekg's default for what a server takes, which leaves out the UPDATE opcode this server is for.
func acceptUpdates(header dns.Header) dns.MsgAcceptAction {
	if (header.Bits>>11)&0xF == dns.OpcodeUpdate {
		return dns.MsgAccept
	}
	return dns.DefaultMsgAcceptFunc(header)
}

// settings are the provider's settings for this server, as the platform stores them.
func (d *dnsDouble) settings() map[string]any {
	return map[string]any{"server": d.host, "port": d.port, "zone": d.zone, "keyName": d.keyName, "algorithm": "hmac-sha256"}
}

func (d *dnsDouble) txt(name string) []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.records[name]...)
}

func (d *dnsDouble) allRecords() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, values := range d.records {
		n += len(values)
	}
	return n
}

func (d *dnsDouble) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	reply := new(dns.Msg)
	reply.SetReply(r)
	tsig := r.IsTsig()
	if status := w.TsigStatus(); tsig == nil || status != nil {
		// A request that is not signed, or not with a key and secret this server has, is answered unsigned, with the reason in a TSIG record.
		code := uint16(dns.RcodeBadSig)
		if status == dns.ErrSecret {
			code = dns.RcodeBadKey
		}
		reply.Rcode = dns.RcodeNotAuth
		reply.Extra = append(reply.Extra, &dns.TSIG{
			Hdr: dns.RR_Header{Name: tsigName(tsig, d.keyName), Rrtype: dns.TypeTSIG, Class: dns.ClassANY}, Algorithm: dns.HmacSHA256,
			TimeSigned: uint64(time.Now().Unix()), Fudge: 300, OrigId: r.Id, Error: code,
		})
		packed, _ := reply.Pack()
		_, _ = w.Write(packed)
		return
	}
	d.mu.Lock()
	d.updates++
	switch {
	case r.Opcode != dns.OpcodeUpdate:
		reply.Rcode = dns.RcodeNotImplemented
	case len(r.Question) != 1 || strings.ToLower(strings.TrimSuffix(r.Question[0].Name, ".")) != d.zone:
		reply.Rcode = dns.RcodeNotAuth
	default:
		for _, rr := range r.Ns {
			txt, ok := rr.(*dns.TXT)
			name := strings.ToLower(strings.TrimSuffix(rr.Header().Name, "."))
			if !ok || (name != d.zone && !strings.HasSuffix(name, "."+d.zone)) {
				reply.Rcode = dns.RcodeNotZone
				break
			}
			value := strings.Join(txt.Txt, "")
			switch rr.Header().Class {
			case dns.ClassINET:
				d.records[name] = append(d.records[name], value)
			case dns.ClassNONE:
				kept := d.records[name][:0:0]
				for _, v := range d.records[name] {
					if v != value {
						kept = append(kept, v)
					}
				}
				d.records[name] = kept
			case dns.ClassANY:
				delete(d.records, name)
			}
		}
	}
	d.mu.Unlock()
	reply.SetTsig(dns.Fqdn(d.keyName), dns.HmacSHA256, 300, time.Now().Unix())
	_ = w.WriteMsg(reply)
}

func tsigName(tsig *dns.TSIG, fallback string) string {
	if tsig != nil {
		return tsig.Hdr.Name
	}
	return dns.Fqdn(fallback)
}

// wapiDouble is an Infoblox grid master's WAPI for TXT records, with HTTP Basic authentication, over TLS with a certificate of its own.
type wapiDouble struct {
	server   *httptest.Server
	user     string
	password string
	zone     string

	mu       sync.Mutex
	records  map[string]wapiRecord
	requests []string
	next     int
}

type wapiRecord struct{ Name, Text, View string }

func startWAPI(t *testing.T, zone, user, password string) *wapiDouble {
	t.Helper()
	d := &wapiDouble{user: user, password: password, zone: zone, records: map[string]wapiRecord{}}
	d.server = httptest.NewTLSServer(http.HandlerFunc(d.serve))
	t.Cleanup(d.server.Close)
	return d
}

func (d *wapiDouble) settings() map[string]any {
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d.server.Certificate().Raw})
	return map[string]any{"url": d.server.URL + "/wapi/v2.12", "zone": d.zone, "view": "default", "caCertificate": string(certificate)}
}

func (d *wapiDouble) credentials() string { return d.user + ":" + d.password }

func (d *wapiDouble) texts(name string) []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var texts []string
	for _, r := range d.records {
		if r.Name == name {
			texts = append(texts, r.Text)
		}
	}
	return texts
}

func (d *wapiDouble) serve(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.requests = append(d.requests, r.Method+" "+r.URL.Path)
	if user, password, ok := r.BasicAuth(); !ok || user != d.user || password != d.password {
		http.Error(w, `{"Error":"AdmConProtoError: Client.Ibap.Auth","code":"Client.Ibap.Auth","text":"Authorization Required"}`, http.StatusUnauthorized)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/wapi/v2.12/")
	w.Header().Set("content-type", "application/json")
	switch {
	case r.Method == http.MethodGet && path == "record:txt":
		found := []map[string]string{}
		for ref, rec := range d.records {
			if rec.Name == r.URL.Query().Get("name") && rec.Text == r.URL.Query().Get("text") && rec.View == r.URL.Query().Get("view") {
				found = append(found, map[string]string{"_ref": ref})
			}
		}
		_ = json.NewEncoder(w).Encode(found)
	case r.Method == http.MethodPost && path == "record:txt":
		var body struct{ Name, Text, View string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		d.next++
		ref := "record:txt/" + base64.RawStdEncoding.EncodeToString([]byte("txt"+strconv.Itoa(d.next))) + ":" + body.Name + "/" + body.View
		d.records[ref] = wapiRecord{Name: body.Name, Text: body.Text, View: body.View}
		_ = json.NewEncoder(w).Encode(ref)
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "record:txt/"):
		delete(d.records, path)
		_ = json.NewEncoder(w).Encode(path)
	default:
		http.Error(w, `{"text":"not found"}`, http.StatusNotFound)
	}
}

var _ = tls.VersionTLS12
