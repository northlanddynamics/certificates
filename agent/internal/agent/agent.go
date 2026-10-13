// Package agent is what the Agent does: register with the platform once, then keep its identity and poll for work, only ever
// connecting outbound. Registration generates the identity key here and sends the platform a CSR, never the key (ADR 0002).
package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"runtime"
	"sync/atomic"
	"time"

	"certificate-platform/agent/internal/dnsrelay"
	"certificate-platform/agent/internal/identity"
	"certificate-platform/agent/internal/platform"
)

// Clock is time as the Agent sees it, so that tests need not wait for it.
type Clock interface {
	Now() time.Time
	// Sleep waits for d, or returns the context's error when it ends first.
	Sleep(ctx context.Context, d time.Duration) error
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }
func (realClock) Sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Config is what the Agent is run with.
type Config struct {
	// StateDir holds the identity: only the service account may read it.
	StateDir string
	// Version is what the Agent reports to the platform.
	Version string
	// RootCAs verify the platform's TLS certificate; nil means the host's roots.
	RootCAs *x509.CertPool
	Clock   Clock
	Log     *slog.Logger
	// BackoffMin and BackoffMax bound the wait after a failure, which doubles from the first up to the second.
	BackoffMin, BackoffMax time.Duration
	// OS and Arch are what registration reports; they default to the host's.
	OS, Arch string
	// ScriptTimeout stops a Deployment Script that has not ended; ten minutes when zero.
	ScriptTimeout time.Duration
}

func (c *Config) defaults() {
	if c.Clock == nil {
		c.Clock = realClock{}
	}
	if c.Log == nil {
		c.Log = slog.Default()
	}
	if c.BackoffMin == 0 {
		c.BackoffMin = 5 * time.Second
	}
	if c.BackoffMax == 0 {
		c.BackoffMax = 5 * time.Minute
	}
	if c.OS == "" {
		c.OS = runtime.GOOS
	}
	if c.Arch == "" {
		c.Arch = runtime.GOARCH
	}
}

// ErrIdentityRejected means the platform no longer accepts this Agent: it was revoked, or it was away so long that its
// identity certificate ended. Only registering again, with a new token, brings it back.
var ErrIdentityRejected = errors.New("the platform no longer accepts this Agent's identity: it was revoked or its identity certificate has ended; register it again with a new token")

// Register binds the Agent to the Organization the token belongs to, and stores the identity the platform issues.
func Register(ctx context.Context, cfg Config, platformURL, token, hostName string) error {
	cfg.defaults()
	client, err := platform.NewClient(platformURL, platform.Options{RootCAs: cfg.RootCAs, Now: cfg.Clock.Now})
	if err != nil {
		return err
	}
	if (cfg.OS != "linux" && cfg.OS != "windows") || (cfg.Arch != "amd64" && cfg.Arch != "arm64") {
		return fmt.Errorf("the Agent runs on Linux and Windows, on amd64 and arm64, not on %s/%s", cfg.OS, cfg.Arch)
	}
	key, err := identity.NewKey()
	if err != nil {
		return err
	}
	csr, err := identity.CSR(key)
	if err != nil {
		return err
	}
	res, err := client.Register(ctx, platform.RegistrationRequest{
		Token: token, CSR: string(csr), HostName: hostName, OS: cfg.OS, Arch: cfg.Arch, Version: cfg.Version,
	})
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}
	id, err := identity.New(key, []byte(res.Certificate))
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}
	if err := (identity.Store{Dir: cfg.StateDir}).Save(id, identity.Meta{PlatformURL: platformURL, AgentID: res.AgentID}); err != nil {
		return fmt.Errorf("the identity could not be stored: %w", err)
	}
	cfg.Log.Info("registered", "agentId", res.AgentID, "identityNotAfter", id.Cert.NotAfter)
	return nil
}

// Run polls the platform until the context ends, rotating its identity certificate before it expires. A platform it cannot
// reach is waited for with growing pauses, not given up on; only the platform refusing the Agent's identity ends it.
func Run(ctx context.Context, cfg Config) error {
	cfg.defaults()
	store := identity.Store{Dir: cfg.StateDir}
	id, meta, err := store.Load()
	if err != nil {
		return err
	}
	var current atomic.Pointer[tls.Certificate]
	current.Store(id.TLS())
	client, err := platform.NewClient(meta.PlatformURL, platform.Options{
		RootCAs:  cfg.RootCAs,
		Identity: current.Load,
		Now:      cfg.Clock.Now,
	})
	if err != nil {
		return err
	}
	r := &runner{cfg: cfg, store: store, client: client, id: id, current: &current}
	return r.run(ctx)
}

type runner struct {
	cfg     Config
	store   identity.Store
	client  *platform.Client
	id      *identity.Identity
	current *atomic.Pointer[tls.Certificate]
}

func (r *runner) run(ctx context.Context) error {
	failures := 0
	for {
		wait, err := r.cycle(ctx)
		switch {
		case ctx.Err() != nil:
			return nil
		case platform.Rejected(err):
			return ErrIdentityRejected
		case err != nil:
			failures++
			wait = r.backoff(failures)
			r.cfg.Log.Warn("the platform could not be reached or refused the call; will try again", "error", err, "retryIn", wait.String())
		default:
			failures = 0
		}
		if err := r.cfg.Clock.Sleep(ctx, wait); err != nil {
			return nil
		}
	}
}

// cycle is one pass: rotate the identity if it is due, then poll. It returns how long to wait before the next.
func (r *runner) cycle(ctx context.Context) (time.Duration, error) {
	// A failed rotation is tried again next pass; the Agent keeps polling on the identity it has until then.
	rotationErr := r.rotateIfDue(ctx)
	if platform.Rejected(rotationErr) {
		return 0, rotationErr
	}
	if rotationErr != nil {
		r.cfg.Log.Warn("the identity certificate could not be rotated", "error", rotationErr)
	}
	res, err := r.client.Poll(ctx, r.cfg.Version)
	if err != nil {
		return 0, err
	}
	for _, item := range res.Items {
		if err := r.handle(ctx, item); err != nil {
			return 0, err
		}
	}
	wait := time.Duration(res.PollAfterSeconds) * time.Second
	if wait < time.Second {
		wait = time.Second
	}
	return wait, nil
}

// handle carries out a work item and reports how it went. Only the platform refusing the Agent's identity is an error: an
// item that failed has been reported as failed, and one that could not be reported is the platform's to give up on.
func (r *runner) handle(ctx context.Context, item platform.WorkItem) error {
	var result platform.WorkResult
	switch {
	case dnsrelay.Handles(item.Type):
		result = r.relayDNS(ctx, item)
	case item.Type == workGenerateKey:
		result = r.generateKey(item)
	case item.Type == workRun:
		result = r.runDeployment(ctx, item)
	default:
		r.cfg.Log.Warn("ignoring a work item of a type this Agent does not know", "id", item.ID, "type", item.Type)
		return nil
	}
	if err := r.client.ReportResult(ctx, item.ID, result); err != nil {
		if platform.Rejected(err) {
			return err
		}
		// A platform that stopped waiting (it asked another Agent) refuses a late report; neither that nor an outage is the Agent's to retry.
		r.cfg.Log.Warn("the result of a work item could not be reported", "id", item.ID, "error", err)
	}
	return nil
}

// relayDNS carries out a DNS Provider operation.
func (r *runner) relayDNS(ctx context.Context, item platform.WorkItem) platform.WorkResult {
	// The work item holds the provider's credentials: it is logged by its id and type, never by what it carries.
	if failure := dnsrelay.Carry(ctx, item.Type, item.Payload); failure != nil {
		r.cfg.Log.Warn("a DNS Provider operation failed", "id", item.ID, "type", item.Type, "kind", failure.Kind, "error", failure.Message)
		return platform.WorkResult{Kind: failure.Kind, Error: failure.Message}
	}
	r.cfg.Log.Info("carried out a DNS Provider operation", "id", item.ID, "type", item.Type)
	return platform.WorkResult{OK: true}
}

// due is when the identity certificate is rotated: with a third of its life left.
func due(cert *x509.Certificate) time.Time {
	life := cert.NotAfter.Sub(cert.NotBefore)
	return cert.NotBefore.Add(life * 2 / 3)
}

func (r *runner) rotateIfDue(ctx context.Context) error {
	if r.cfg.Clock.Now().Before(due(r.id.Cert)) {
		return nil
	}
	// A new key every time, which never leaves the host; only its CSR does.
	key, err := identity.NewKey()
	if err != nil {
		return err
	}
	csr, err := identity.CSR(key)
	if err != nil {
		return err
	}
	res, err := r.client.RotateIdentity(ctx, string(csr))
	if err != nil {
		return err
	}
	next, err := identity.New(key, []byte(res.Certificate))
	if err != nil {
		return err
	}
	// Stored before it is used, so a restart finds the identity the platform will accept.
	if err := r.store.SaveIdentity(next); err != nil {
		return fmt.Errorf("the new identity could not be stored: %w", err)
	}
	r.id = next
	r.current.Store(next.TLS())
	r.client.Reset()
	r.cfg.Log.Info("rotated the identity certificate", "notAfter", next.Cert.NotAfter)
	return nil
}

// backoff doubles from BackoffMin up to BackoffMax, with some jitter so that Agents that lost the platform together do not return together.
func (r *runner) backoff(failures int) time.Duration {
	d := r.cfg.BackoffMin
	for i := 1; i < failures && d < r.cfg.BackoffMax; i++ {
		d *= 2
	}
	if d > r.cfg.BackoffMax {
		d = r.cfg.BackoffMax
	}
	return d - time.Duration(rand.Int64N(int64(d)/5+1))
}
