// Package platform is the Agent's client for the platform's Agent protocol (agent/contract/openapi.json). The Agent only
// ever connects outbound, over HTTPS: to the platform URL it was registered with, presenting its identity certificate
// (mTLS) on every call but its registration.
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

// Rejected reports whether the platform no longer accepts the Agent's identity (it is revoked, or its certificate ended or
// was replaced): retrying cannot help, only registering again can.
func Rejected(err error) bool {
	var status *StatusError
	return errors.As(err, &status) && status.Status == http.StatusUnauthorized
}

// Options are what a Client needs besides where to connect.
type Options struct {
	// RootCAs verify the platform's TLS certificate; nil means the host's roots.
	RootCAs *x509.CertPool
	// Identity returns the client certificate to present, or nil when the Agent has none yet (registering).
	Identity func() *tls.Certificate
	// Now is the clock certificates are checked against.
	Now func() time.Time
}

// Client speaks the Agent protocol.
type Client struct {
	base      *url.URL
	http      *http.Client
	transport *http.Transport
}

// NewClient refuses a platform URL that is not HTTPS: the Agent does not speak to the platform in the clear.
func NewClient(platformURL string, opts Options) (*Client, error) {
	base, err := url.Parse(platformURL)
	if err != nil || base.Host == "" {
		return nil, fmt.Errorf("%q is not a platform URL", platformURL)
	}
	if base.Scheme != "https" {
		return nil, fmt.Errorf("the platform URL must be https (the Agent connects only over HTTPS), not %q", base.Scheme)
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    opts.RootCAs,
			Time:       now,
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				if opts.Identity != nil {
					if cert := opts.Identity(); cert != nil {
						return cert, nil
					}
				}
				return &tls.Certificate{}, nil
			},
		},
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		MaxIdleConns:          2,
	}
	return &Client{
		base:      base,
		transport: transport,
		http: &http.Client{
			Transport: transport,
			// A redirect would send the Agent's identity somewhere the administrator did not register it with.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// Reset drops the connections held open, so that the next call presents the identity then current (after a rotation).
func (c *Client) Reset() { c.transport.CloseIdleConnections() }

type RegistrationRequest struct {
	Token    string `json:"token"`
	CSR      string `json:"csr"`
	HostName string `json:"hostName"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Version  string `json:"version"`
}

type RegistrationResponse struct {
	AgentID          string `json:"agentId"`
	Certificate      string `json:"certificate"`
	NotAfter         string `json:"notAfter"`
	PollAfterSeconds int    `json:"pollAfterSeconds"`
}

// Register is Agent Registration: the token and a CSR for the key the Agent keeps, for an identity certificate.
func (c *Client) Register(ctx context.Context, req RegistrationRequest) (*RegistrationResponse, error) {
	var res RegistrationResponse
	return &res, c.post(ctx, "/api/agent/registration", req, &res)
}

// WorkItem is something the platform asks the Agent to do. The platform has none to ask yet.
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

type identityRequest struct {
	CSR string `json:"csr"`
}

type IdentityResponse struct {
	Certificate string `json:"certificate"`
	NotAfter    string `json:"notAfter"`
}

// RotateIdentity sends a CSR for a new key and receives the new identity certificate.
func (c *Client) RotateIdentity(ctx context.Context, csr string) (*IdentityResponse, error) {
	var res IdentityResponse
	return &res, c.post(ctx, "/api/agent/identity", identityRequest{CSR: csr}, &res)
}

func (c *Client) post(ctx context.Context, path string, body, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base.JoinPath(path).String(), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("accept", "application/json")
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
