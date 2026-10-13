// Package agent is what the Agent does: register with the platform once, then keep its credential and poll for work, only
// ever connecting outbound. The credential is a secret (ADR 0006): it is stored before it is used and never logged.
package agent

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"runtime"
	"sync"
	"time"

	"certificate-platform/agent/internal/credential"
	"certificate-platform/agent/internal/dnsrelay"
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
	// StateDir holds the credential: only the service account may read it.
	StateDir string
	// Version is what the Agent reports to the platform.
	Version string
	// RootCAs verify the platform's TLS certificate; nil means the host's roots.
	RootCAs *x509.CertPool
	Clock   Clock
	Log     *slog.Logger
	// BackoffMin and BackoffMax bound the wait after a failure, which doubles from the first up to the second.
	BackoffMin, BackoffMax time.Duration
	// OS and Arch are what registration reports (the platform's names: linux, windows or macos; amd64 or arm64); they default
	// to the host's.
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
		c.OS = PlatformOS(runtime.GOOS)
	}
	if c.Arch == "" {
		c.Arch = runtime.GOARCH
	}
}

// PlatformOS is the name the platform has for a Go operating system: linux, windows, and macos for darwin. Any other is
// returned as it is, for Register to refuse.
func PlatformOS(goos string) string {
	if goos == "darwin" {
		return "macos"
	}
	return goos
}

// ErrCredentialRejected means the platform no longer accepts this Agent: it was revoked, or it was away so long that its
// credential ended. Only registering again, with a new token, brings it back.
var ErrCredentialRejected = errors.New("the platform no longer accepts this Agent's credential: it was revoked or its credential has ended; register it again with a new token")

// expiry is when a credential ends, as the platform wrote it.
func expiry(raw string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, errors.New("the platform's answer holds no valid expiry for the credential")
	}
	return t, nil
}

// Register binds the Agent to the Organization the token belongs to, and stores the credential the platform issues.
func Register(ctx context.Context, cfg Config, platformURL, token, hostName string) error {
	cfg.defaults()
	client, err := platform.NewClient(platformURL, platform.Options{RootCAs: cfg.RootCAs})
	if err != nil {
		return err
	}
	if (cfg.OS != "linux" && cfg.OS != "windows" && cfg.OS != "macos") || (cfg.Arch != "amd64" && cfg.Arch != "arm64") {
		return fmt.Errorf("the Agent runs on Linux, Windows and macOS, on amd64 and arm64, not on %s/%s", cfg.OS, cfg.Arch)
	}
	res, err := client.Register(ctx, platform.RegistrationRequest{
		Token: token, HostName: hostName, OS: cfg.OS, Arch: cfg.Arch, Version: cfg.Version,
	})
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}
	expiresAt, err := expiry(res.ExpiresAt)
	if err != nil || res.Credential == "" {
		return errors.New("registration failed: the platform's answer holds no credential")
	}
	record := credential.Record{PlatformURL: platformURL, AgentID: res.AgentID, Credential: res.Credential, IssuedAt: cfg.Clock.Now(), ExpiresAt: expiresAt}
	if err := (credential.Store{Dir: cfg.StateDir}).Save(record); err != nil {
		// The credential is shown only once, so the Agent cannot be used: the token is spent and it must register again.
		return fmt.Errorf("the credential could not be stored (the registration token is used up, so register again with a new one): %w", err)
	}
	cfg.Log.Info("registered", "agentId", res.AgentID, "credentialExpiresAt", expiresAt)
	return nil
}

// Run polls the platform until the context ends, rotating its credential before it expires. A platform it cannot
// reach is waited for with growing pauses, not given up on; only the platform refusing the Agent's credential ends it.
func Run(ctx context.Context, cfg Config) error {
	cfg.defaults()
	store := credential.Store{Dir: cfg.StateDir}
	record, err := store.Load()
	if err != nil {
		return err
	}
	r := &runner{cfg: cfg, store: store, record: record}
	// The client asks the runner for the credential on every call, so a rotation takes effect on the next.
	r.client, err = platform.NewClient(record.PlatformURL, platform.Options{RootCAs: cfg.RootCAs, Credential: r.credential})
	if err != nil {
		return err
	}
	return r.run(ctx)
}

type runner struct {
	cfg    Config
	store  credential.Store
	client *platform.Client
	mu     sync.RWMutex
	record credential.Record
}

func (r *runner) credential() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.record.Credential
}

func (r *runner) run(ctx context.Context) error {
	failures := 0
	for {
		wait, err := r.cycle(ctx)
		switch {
		case ctx.Err() != nil:
			return nil
		case platform.Rejected(err):
			return ErrCredentialRejected
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

// cycle is one pass: rotate the credential if it is due, then poll. It returns how long to wait before the next.
func (r *runner) cycle(ctx context.Context) (time.Duration, error) {
	// A failed rotation is tried again next pass; the Agent keeps polling on the credential it has until then.
	rotationErr := r.rotateIfDue(ctx)
	if platform.Rejected(rotationErr) {
		return 0, rotationErr
	}
	if rotationErr != nil {
		r.cfg.Log.Warn("the credential could not be rotated", "error", rotationErr)
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

// handle carries out a work item and reports how it went. Only the platform refusing the Agent's credential is an error: an
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

// rotateIfDue replaces the credential once a third of its life is left. A rotation whose answer never arrived has left the
// platform accepting the old credential as well as a new one the Agent does not have, so it is asked again with the old, on
// the next pass, until an answer arrives.
func (r *runner) rotateIfDue(ctx context.Context) error {
	if r.cfg.Clock.Now().Before(r.record.RotationDue()) {
		return nil
	}
	res, err := r.client.RotateCredential(ctx)
	if err != nil {
		return err
	}
	expiresAt, err := expiry(res.ExpiresAt)
	if err != nil || res.Credential == "" {
		return errors.New("the platform's answer to the rotation holds no credential")
	}
	next := r.record
	next.Credential, next.IssuedAt, next.ExpiresAt = res.Credential, r.cfg.Clock.Now(), expiresAt
	// Stored before it is used, so a restart finds the credential the platform will accept, and a credential that could not be
	// stored is not used: the old one still works until the new one is first used.
	if err := r.store.Save(next); err != nil {
		return fmt.Errorf("the new credential could not be stored: %w", err)
	}
	r.mu.Lock()
	r.record = next
	r.mu.Unlock()
	r.cfg.Log.Info("rotated the credential", "expiresAt", expiresAt)
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
