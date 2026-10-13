package dnsrelay

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// The RFC 2136 DNS Provider: dynamic updates authenticated with a TSIG key (RFC 8945), spoken over TCP, which every such
// server accepts and which needs no retries. Every reply must carry a valid signature, or a man in the middle could say
// yes for the server.

const (
	txtTTL         = 60
	tsigFudge      = 300
	defaultTimeout = 10 * time.Second
)

var tsigAlgorithms = map[string]string{
	"hmac-sha256": dns.HmacSHA256,
	"hmac-sha384": dns.HmacSHA384,
	"hmac-sha512": dns.HmacSHA512,
	"hmac-sha1":   dns.HmacSHA1,
	"hmac-md5":    dns.HmacMD5,
}

type rfc2136Settings struct {
	Server    string `json:"server"`
	Port      int    `json:"port"`
	Zone      string `json:"zone"`
	KeyName   string `json:"keyName"`
	Algorithm string `json:"algorithm"`
}

type rfc2136 struct {
	server, zone, keyName string
	port                  int
	algorithm             string
	secret                string // as the TSIG library wants it: base64
	timeout               time.Duration
}

func newRfc2136(raw json.RawMessage, secret string) (Provider, error) {
	var s rfc2136Settings
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, rejected("the DNS Provider's settings cannot be read")
	}
	if s.Port == 0 {
		s.Port = 53
	}
	if s.Algorithm == "" {
		s.Algorithm = "hmac-sha256"
	}
	zone, zoneOK := domainName(s.Zone)
	keyName, keyOK := domainName(s.KeyName)
	algorithm, algorithmOK := tsigAlgorithms[s.Algorithm]
	if s.Server == "" || s.Port < 1 || s.Port > 65535 || !zoneOK || !keyOK || !algorithmOK {
		return nil, rejected("the DNS Provider's settings are not those of an RFC 2136 provider")
	}
	// A TSIG key is written in the server's configuration as base64; one that is not cannot be the server's.
	if _, err := base64.StdEncoding.DecodeString(secret); err != nil {
		return nil, rejected("the DNS Provider's secret is not a base64 TSIG key")
	}
	return &rfc2136{server: s.Server, port: s.Port, zone: zone, keyName: keyName, algorithm: algorithm, secret: secret, timeout: defaultTimeout}, nil
}

func (p *rfc2136) address() string { return net.JoinHostPort(p.server, strconv.Itoa(p.port)) }

// send makes the server apply the update to the zone, or says why not.
func (p *rfc2136) send(ctx context.Context, update func(m *dns.Msg)) error {
	m := new(dns.Msg)
	m.SetUpdate(dns.Fqdn(p.zone))
	update(m)
	keyName := dns.Fqdn(p.keyName)
	m.SetTsig(keyName, p.algorithm, tsigFudge, time.Now().Unix())

	client := &dns.Client{Net: "tcp", Timeout: p.timeout, TsigSecret: map[string]string{keyName: p.secret}}
	reply, _, err := client.ExchangeContext(ctx, m, p.address())
	if reply == nil {
		return p.unreachableBecause(err)
	}
	if reply.Id != m.Id {
		return rejected("%s answered a different request", p.address())
	}

	tsig := reply.IsTsig()
	if tsig != nil {
		switch tsig.Error {
		case dns.RcodeBadKey:
			return rejected("the server does not know the TSIG key %q (BADKEY)", p.keyName)
		case dns.RcodeBadSig:
			return rejected("the server rejected the TSIG signature (BADSIG): the key's secret or algorithm differs from the server's")
		case dns.RcodeBadTime:
			return rejected("the server rejected the TSIG time (BADTIME): the platform's clock and the server's are more than %d minutes apart", tsigFudge/60)
		case 0:
		default:
			return rejected("the server rejected the TSIG signature (error code %d)", tsig.Error)
		}
	}
	if tsig == nil && reply.Rcode == dns.RcodeSuccess {
		return rejected("the server's reply was not signed with the TSIG key, so it cannot be trusted")
	}
	if tsig != nil && err != nil {
		return rejected("the server's reply was not signed correctly with the TSIG key, so it cannot be trusted")
	}

	switch reply.Rcode {
	case dns.RcodeSuccess:
		return nil
	case dns.RcodeRefused:
		return rejected("the server refused the update (REFUSED): the TSIG key %q may not update that name in %s, or the zone takes no dynamic updates", p.keyName, p.zone)
	case dns.RcodeNotAuth:
		return rejected("the server is not authoritative for %s (NOTAUTH)", p.zone)
	case dns.RcodeNotZone:
		return rejected("the name is not inside the zone %s as the server has it (NOTZONE)", p.zone)
	case dns.RcodeFormatError:
		return rejected("the server did not understand the update (FORMERR)")
	case dns.RcodeServerFailure:
		return rejected("the server failed to process the update (SERVFAIL)")
	case dns.RcodeNotImplemented:
		return rejected("the server does not support dynamic updates (NOTIMP)")
	default:
		return rejected("the server answered with error code %d", reply.Rcode)
	}
}

// unreachableBecause says why the server did not answer, as the platform's own provider does.
func (p *rfc2136) unreachableBecause(err error) error {
	var netErr net.Error
	switch {
	case errors.As(err, &netErr) && netErr.Timeout(), errors.Is(err, context.DeadlineExceeded):
		return unreachable("%s did not answer within %s seconds", p.address(), strconv.FormatFloat(p.timeout.Seconds(), 'f', -1, 64))
	case errors.Is(err, context.Canceled):
		return unreachable("%s was not asked: the Agent is stopping", p.address())
	case err != nil && (strings.Contains(err.Error(), "EOF") || strings.Contains(err.Error(), "closed")):
		return unreachable("%s closed the connection without answering", p.address())
	case err != nil:
		return unreachable("%s could not be reached: %s", p.address(), reason(err))
	default:
		return unreachable("%s did not answer", p.address())
	}
}

// reason is the part of a network error that says what happened: "connection refused", not the addresses around it.
func reason(err error) string {
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		return op.Err.Error()
	}
	return err.Error()
}

func txtRecord(name, value string, class uint16, ttl uint32) *dns.TXT {
	var chunks []string
	for len(value) > 255 {
		chunks, value = append(chunks, value[:255]), value[255:]
	}
	chunks = append(chunks, value)
	return &dns.TXT{Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeTXT, Class: class, Ttl: ttl}, Txt: chunks}
}

func (p *rfc2136) Present(ctx context.Context, record Record) error {
	name, err := nameInZone(p.zone, record)
	if err != nil {
		return err
	}
	return p.send(ctx, func(m *dns.Msg) { m.Insert([]dns.RR{txtRecord(name, record.Value, dns.ClassINET, txtTTL)}) })
}

// CleanUp deletes exactly this record from the name's set, which is what lets several challenges share a name.
func (p *rfc2136) CleanUp(ctx context.Context, record Record) error {
	name, err := nameInZone(p.zone, record)
	if err != nil {
		return err
	}
	return p.send(ctx, func(m *dns.Msg) { m.Remove([]dns.RR{txtRecord(name, record.Value, dns.ClassINET, 0)}) })
}

func (p *rfc2136) Test(ctx context.Context) error { return testByThrowawayRecord(ctx, p.zone, p) }
