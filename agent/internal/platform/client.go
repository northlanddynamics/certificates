// Package platform is the Agent's client for the platform's Agent protocol (agent/contract/openapi.json). The Agent only
// ever connects outbound, over HTTPS (plain HTTP only to a loopback address, for development): to the platform URL it was
// registered with, presenting its credential (ADR 0006) as a bearer token on every call but its registration.
package platform

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// maxResponse bounds what is read from the platform, whatever it sends.
const maxResponse = 4 << 20

// StatusError is the platform answering with an error.
type StatusError struct {
	Status  int
	Message string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("the platform answered %d: %s", e.Status, e.Message)
}

// Rejected reports whether the platform no longer accepts the Agent's credential (it is revoked, or its credential ended or
// was replaced): retrying cannot help, only registering again can.
func Rejected(err error) bool {
	var status *StatusError
	return errors.As(err, &status) && status.Status == http.StatusUnauthorized
}

// Options are what a Client needs besides where to connect.
type Options struct {
	// RootCAs verify the platform's TLS certificate; nil means the host's roots.
	RootCAs *x509.CertPool
	// Credential returns the credential to present, or "" when the Agent has none yet (registering). It is asked for on every
	// call, so that a rotation takes effect on the next.
	Credential func() string
}

// Client speaks the Agent protocol.
type Client struct {
	base       *url.URL
	http       *http.Client
	credential func() string
}

// ValidatePlatformURL says why the Agent will not talk to a platform URL, or returns it parsed. The Agent connects only over
// HTTPS, except to a loopback host (localhost, 127.0.0.0/8, ::1), where plain HTTP is accepted so that development needs no
// certificate: nothing on that path leaves the host.
func ValidatePlatformURL(platformURL string) (*url.URL, error) {
	base, err := url.Parse(platformURL)
	if err != nil || base.Host == "" || base.Hostname() == "" {
		return nil, fmt.Errorf("%q is not a platform URL", platformURL)
	}
	switch base.Scheme {
	case "https":
	case "http":
		if !isLoopback(base.Hostname()) {
			return nil, fmt.Errorf("the platform URL must be https (the Agent connects over plain http only to a loopback address), not %q", platformURL)
		}
	default:
		return nil, fmt.Errorf("the platform URL must be https, not %q", base.Scheme)
	}
	if base.User != nil {
		return nil, errors.New("the platform URL must not hold a user name or password")
	}
	return base, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// NewClient refuses a platform URL that ValidatePlatformURL refuses.
func NewClient(platformURL string, opts Options) (*Client, error) {
	base, err := ValidatePlatformURL(platformURL)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: opts.RootCAs},
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		MaxIdleConns:          2,
	}
	return &Client{
		base:       base,
		credential: opts.Credential,
		http: &http.Client{
			Transport: transport,
			// A redirect would send the Agent's credential somewhere the administrator did not register it with.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

type RegistrationRequest struct {
	Token    string `json:"token"`
	HostName string `json:"hostName"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Version  string `json:"version"`
}

type RegistrationResponse struct {
	AgentID          string `json:"agentId"`
	Credential       string `json:"credential"`
	ExpiresAt        string `json:"expiresAt"`
	PollAfterSeconds int    `json:"pollAfterSeconds"`
}

// Register is Agent Registration: the token, for the Agent's credential, which the platform shows only in this answer.
func (c *Client) Register(ctx context.Context, req RegistrationRequest) (*RegistrationResponse, error) {
	var res RegistrationResponse
	return &res, c.post(ctx, "/api/agent/registration", req, &res)
}

// WorkItem is something the platform asks the Agent to do.
type WorkItem struct {
	ID      string                     `json:"id"`
	Type    string                     `json:"type"`
	Payload map[string]json.RawMessage `json:"payload"`
}

type PollRequest struct {
	Version string `json:"version"`
}

type PollResponse struct {
	Items            []WorkItem `json:"items"`
	PollAfterSeconds int        `json:"pollAfterSeconds"`
}

// Poll is the heartbeat: it reports the version and brings the work items.
func (c *Client) Poll(ctx context.Context, version string) (*PollResponse, error) {
	var res PollResponse
	return &res, c.post(ctx, "/api/agent/poll", PollRequest{Version: version}, &res)
}

// RunReport is how a Deployment Script went. ExitCode is null when the script was not started, and Output then says why.
type RunReport struct {
	StartedAt       string `json:"startedAt"`
	FinishedAt      string `json:"finishedAt"`
	ExitCode        *int   `json:"exitCode"`
	Output          string `json:"output"`
	OutputTruncated bool   `json:"outputTruncated"`
}

// WorkResult is how a work item went. Kind says how a DNS Provider or ADCS operation failed: "rejected" when the service
// answered and said no, "unreachable" when it did not answer. Error is for a person to read and holds no secret. CSR is for
// the key the Agent made (never the key), Run is how a Deployment Script went, Discovery what it found at an ADCS CA, and
// Submission what ADCS answered a request with, or holds it as now.
type WorkResult struct {
	OK         bool        `json:"ok"`
	Kind       string      `json:"kind,omitempty"`
	Error      string      `json:"error,omitempty"`
	CSR        string      `json:"csr,omitempty"`
	Run        *RunReport  `json:"run,omitempty"`
	Discovery  *Discovery  `json:"discovery,omitempty"`
	Submission *Submission `json:"submission,omitempty"`
}

// Submission is what `adcs.submit` or `adcs.check` got from ADCS: its disposition ("issued", "pending" or "denied"), its
// ID of the request, for an issued one the Certificate (PEM), and for a denied one ADCS's disposition message.
type Submission struct {
	Status      string `json:"status"`
	RequestID   string `json:"requestId"`
	Certificate string `json:"certificate,omitempty"`
	Message     string `json:"message,omitempty"`
}

// Discovery is what `adcs.discover` found: the CA's chain (PEM, the CA certificate first, up to its root) and its templates.
type Discovery struct {
	Chain     []string   `json:"chain"`
	Templates []Template `json:"templates"`
}

// Template is a Certificate Template's facts, as the platform takes them.
type Template struct {
	Name               string   `json:"name"`
	OID                string   `json:"oid"`
	DisplayName        string   `json:"displayName"`
	ExtendedKeyUsages  []string `json:"extendedKeyUsages"`
	ValidityDays       int      `json:"validityDays"`
	MinimumKeySize     int      `json:"minimumKeySize"`
	KeyAlgorithms      []string `json:"keyAlgorithms"`
	ManagerApproval    bool     `json:"managerApproval"`
	SubjectFromRequest bool     `json:"subjectFromRequest"`
	Enrollable         bool     `json:"enrollable"`
	Published          bool     `json:"published"`
}

type workResultResponse struct {
	Received bool `json:"received"`
}

// ReportResult tells the platform how a work item went, once.
func (c *Client) ReportResult(ctx context.Context, id string, result WorkResult) error {
	var res workResultResponse
	return c.post(ctx, "/api/agent/work-items/"+url.PathEscape(id)+"/result", result, &res)
}

type CredentialResponse struct {
	Credential string `json:"credential"`
	ExpiresAt  string `json:"expiresAt"`
}

// RotateCredential asks for a new credential, presenting the one it replaces. The old one stays accepted until the new one is
// first used, so a rotation whose answer was lost can be asked again with the old one.
func (c *Client) RotateCredential(ctx context.Context) (*CredentialResponse, error) {
	var res CredentialResponse
	return &res, c.post(ctx, "/api/agent/credential", nil, &res)
}

func (c *Client) post(ctx context.Context, path string, body, out any) error {
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base.JoinPath(path).String(), payload)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("content-type", "application/json")
	}
	req.Header.Set("accept", "application/json")
	if c.credential != nil {
		if credential := c.credential(); credential != "" {
			req.Header.Set("authorization", "Bearer "+credential)
		}
	}
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, maxResponse))
	if err != nil {
		return err
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		var failure struct {
			Error string `json:"error"`
		}
		message := http.StatusText(res.StatusCode)
		if json.Unmarshal(data, &failure) == nil && failure.Error != "" {
			message = failure.Error
		}
		return &StatusError{Status: res.StatusCode, Message: message}
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("the platform's answer to %s cannot be read: %w", path, err)
	}
	return nil
}
