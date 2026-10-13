package dnsrelay

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The Infoblox DNS Provider: TXT records published and removed through the NIOS WAPI (REST over HTTPS, HTTP Basic
// authentication). Nothing is sent over a connection whose certificate is not trusted, which is the system's roots, or the
// one certificate authority the settings name for a grid with its own; and nothing is followed to somewhere else, since the
// credentials go with each request.

var wapiPath = regexp.MustCompile(`^/wapi/v\d+(\.\d+)*$`)

// maxAnswer is the most a WAPI answer may be: a TXT search for one name and text returns a handful of records.
const maxAnswer = 1_000_000

type infobloxSettings struct {
	URL           string `json:"url"`
	Zone          string `json:"zone"`
	View          string `json:"view"`
	CACertificate string `json:"caCertificate"`
}

type infoblox struct {
	base           string
	where          string
	zone, view     string
	user, password string
	client         *http.Client
	timeout        time.Duration
}

func newInfoblox(raw json.RawMessage, secret string) (Provider, error) {
	var s infobloxSettings
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, rejected("the DNS Provider's settings cannot be read")
	}
	u, err := url.Parse(s.URL)
	zone, zoneOK := domainName(s.Zone)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !wapiPath.MatchString(strings.TrimSuffix(u.Path, "/")) || !zoneOK {
		return nil, rejected("the DNS Provider's settings are not those of an Infoblox provider")
	}
	if s.View == "" {
		s.View = "default"
	}
	user, password, ok := strings.Cut(secret, ":")
	if !ok || user == "" || password == "" {
		return nil, rejected("the DNS Provider's secret is not the WAPI user's name and password")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if s.CACertificate != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(s.CACertificate)) {
			return nil, rejected("the DNS Provider's CA certificate is not a PEM certificate")
		}
		tlsConfig.RootCAs = pool
	}
	timeout := defaultTimeout
	return &infoblox{
		base:     u.Scheme + "://" + u.Host + strings.TrimSuffix(u.Path, "/"),
		where:    u.Host,
		zone:     zone,
		view:     s.View,
		user:     user,
		password: password,
		timeout:  timeout,
		client: &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{TLSClientConfig: tlsConfig, Proxy: http.ProxyFromEnvironment, TLSHandshakeTimeout: timeout},
			// The credentials go with each request, so a redirect is an answer, not a place to go.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// wapiText is what the WAPI says is wrong, as it puts it, without the request's own details.
func wapiText(answer any) string {
	switch a := answer.(type) {
	case string:
		return truncate(a)
	case map[string]any:
		for _, key := range []string{"text", "Error"} {
			if text, ok := a[key].(string); ok && text != "" {
				return truncate(text)
			}
		}
	}
	return ""
}

func truncate(s string) string {
	if len(s) > 300 {
		return s[:300]
	}
	return s
}

// call is one WAPI call; it returns its JSON answer, or says why not.
func (p *infoblox) call(ctx context.Context, method, path string, body any) (any, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, p.base+"/"+path, reader)
	if err != nil {
		return nil, rejected("the request to %s cannot be made", p.where)
	}
	request.SetBasicAuth(p.user, p.password)
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := p.client.Do(request)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() || errors.Is(err, context.DeadlineExceeded) {
			return nil, unreachable("%s did not answer within %s seconds", p.where, strconv.FormatFloat(p.timeout.Seconds(), 'f', -1, 64))
		}
		return nil, unreachable("%s could not be reached: %s", p.where, reason(errors.Unwrap(err)))
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxAnswer+1))
	if err != nil {
		return nil, unreachable("%s stopped answering part way", p.where)
	}
	if len(data) > maxAnswer {
		return nil, rejected("%s sent an answer larger than %d MB, which no WAPI would", p.where, maxAnswer/1_000_000)
	}
	var answer any = string(data)
	var decoded any
	if json.Unmarshal(data, &decoded) == nil {
		answer = decoded
	}
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return answer, nil
	}
	reasonText := wapiText(answer)
	suffix := ""
	if reasonText != "" {
		suffix = ": " + reasonText
	}
	switch {
	case response.StatusCode == 401:
		return nil, rejected("Infoblox refused the credentials (401): check the user name and password")
	case response.StatusCode == 403:
		return nil, rejected("Infoblox does not allow the WAPI user to do that (403)%s", suffix)
	case response.StatusCode >= 300 && response.StatusCode < 400:
		return nil, rejected("%s answered with a redirect (%d): check the WAPI URL", p.where, response.StatusCode)
	default:
		return nil, rejected("Infoblox answered %d%s", response.StatusCode, suffix)
	}
}

// find is the references of the TXT records in this view with exactly that name and text.
func (p *infoblox) find(ctx context.Context, name, value string) ([]string, error) {
	query := url.Values{"name": {name}, "text": {value}, "view": {p.view}}
	answer, err := p.call(ctx, http.MethodGet, "record:txt?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}
	found, ok := answer.([]any)
	if !ok {
		return nil, rejected("%s did not answer as a WAPI does", p.where)
	}
	var refs []string
	for _, r := range found {
		if record, ok := r.(map[string]any); ok {
			if ref, ok := record["_ref"].(string); ok {
				refs = append(refs, ref)
			}
		}
	}
	return refs, nil
}

func (p *infoblox) Present(ctx context.Context, record Record) error {
	name, err := nameInZone(p.zone, record)
	if err != nil {
		return err
	}
	if refs, err := p.find(ctx, name, record.Value); err != nil || len(refs) > 0 {
		return err
	}
	_, err = p.call(ctx, http.MethodPost, "record:txt", map[string]any{"name": name, "text": record.Value, "view": p.view, "ttl": txtTTL, "use_ttl": true})
	if failure, ok := err.(*Error); ok && failure.Kind == Rejected {
		// Another present of the same record in between is a success, not Infoblox's "already exists".
		if refs, findErr := p.find(ctx, name, record.Value); findErr == nil && len(refs) > 0 {
			return nil
		}
	}
	return err
}

func (p *infoblox) CleanUp(ctx context.Context, record Record) error {
	name, err := nameInZone(p.zone, record)
	if err != nil {
		return err
	}
	refs, err := p.find(ctx, name, record.Value)
	if err != nil {
		return err
	}
	for _, ref := range refs {
		parts := strings.Split(ref, "/")
		// The reference comes from the server and goes into a path: only a TXT record's is followed.
		if !strings.HasPrefix(ref, "record:txt/") || slices.Contains(parts, "..") || slices.Contains(parts, ".") {
			return rejected("%s named something other than a TXT record to delete", p.where)
		}
		for i, part := range parts {
			// A reference has colons in it, which WAPI takes as they are.
			parts[i] = strings.ReplaceAll(url.PathEscape(part), "%3A", ":")
		}
		if _, err := p.call(ctx, http.MethodDelete, strings.Join(parts, "/"), nil); err != nil {
			return err
		}
	}
	return nil
}

func (p *infoblox) Test(ctx context.Context) error { return testByThrowawayRecord(ctx, p.zone, p) }
