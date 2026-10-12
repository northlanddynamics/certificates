// Seam B: the Agent at its process boundary, run against a stub of the platform built from the platform's own contract
// (internal/platformstub), over real TLS with mutual authentication. Time is a clock the tests move, so rotating an
// identity that lasts 30 days, or waiting out a platform that is down, takes no time.
package agent_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"certificate-platform/agent/internal/agent"
	"certificate-platform/agent/internal/identity"
	"certificate-platform/agent/internal/platform"
	"certificate-platform/agent/internal/platformstub"
)

// clock is time that moves only when the Agent sleeps (by as long as it slept) or the test says so.
type clock struct {
	mu        sync.Mutex
	now       time.Time
	sleeps    []time.Duration
	afterEach func(slept int)
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func (c *clock) Sleep(ctx context.Context, d time.Duration) error {
	c.mu.Lock()
	c.sleeps = append(c.sleeps, d)
	c.now = c.now.Add(d)
	slept, hook := len(c.sleeps), c.afterEach
	c.mu.Unlock()
	if hook != nil {
		hook(slept)
	}
	return ctx.Err()
}

func (c *clock) Sleeps() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.sleeps...)
}

type world struct {
	t     *testing.T
	stub  *platformstub.Stub
	clock *clock
	cfg   agent.Config
}

func newWorld(t *testing.T, opts platformstub.Options) *world {
	t.Helper()
	c := &clock{now: time.Now().UTC().Truncate(time.Second)}
	opts.Clock = c
	stub, err := platformstub.Start(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stub.Close)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(stub.ServerCertificatePEM())
	w := &world{t: t, stub: stub, clock: c, cfg: agent.Config{
		StateDir:   filepath.Join(t.TempDir(), "state"),
		Version:    "1.2.3",
		RootCAs:    roots,
		Clock:      c,
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		BackoffMin: time.Second,
		BackoffMax: 8 * time.Second,
		OS:         "linux",
		Arch:       "amd64",
	}}
	t.Cleanup(func() {
		if v := stub.ContractViolations(); len(v) > 0 {
			t.Errorf("the Agent and the contract disagree: %s", strings.Join(v, "; "))
		}
	})
	return w
}

func (w *world) register() {
	w.t.Helper()
	w.stub.AddToken("agt_good")
	if err := agent.Register(context.Background(), w.cfg, w.stub.URL(), "agt_good", "web-01"); err != nil {
		w.t.Fatal(err)
	}
}

// runUntil runs the Agent until stop reports true after one of its sleeps, and returns how it ended.
func (w *world) runUntil(stop func() bool) error {
	w.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.clock.afterEach = func(int) {
		if stop() {
			cancel()
		}
	}
	done := make(chan error, 1)
	go func() { done <- agent.Run(ctx, w.cfg) }()
	select {
	case err := <-done:
		return err
	case <-time.After(30 * time.Second):
		w.t.Fatal("the Agent did not stop")
		return nil
	}
}

func (w *world) loadIdentity() *identity.Identity {
	w.t.Helper()
	id, _, err := (identity.Store{Dir: w.cfg.StateDir}).Load()
	if err != nil {
		w.t.Fatal(err)
	}
	return id
}

func serialOf(c *x509.Certificate) string { return strings.ToUpper(c.SerialNumber.Text(16)) }

func count(calls []string, path string) int {
	n := 0
	for _, c := range calls {
		if c == path {
			n++
		}
	}
	return n
}

const (
	registration = "/api/agent/registration"
	poll         = "/api/agent/poll"
	rotation     = "/api/agent/identity"
)

func TestRegistrationSendsAMachineIdentityRequestAndNeverTheKey(t *testing.T) {
	w := newWorld(t, platformstub.Options{})
	w.register()

	requests := w.stub.Requests()
	if len(requests) != 1 || requests[0].Path != registration {
		t.Fatalf("expected one registration, got %v", w.stub.Calls())
	}
	if requests[0].ClientCertificate != "" {
		t.Fatal("registration presented a client certificate, which the Agent does not have yet")
	}

	id := w.loadIdentity()
	if id.Key.Curve != elliptic.P256() {
		t.Fatalf("the identity key is on %s, not P-256", id.Key.Curve.Params().Name)
	}
	// The CSR the platform was sent is for the key the Agent kept.
	var sent struct{ CSR, HostName, OS, Arch, Version string }
	decodeJSON(t, requests[0].Body, &sent)
	block, _ := pem.Decode([]byte(sent.CSR))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		t.Fatalf("the CSR is not good: %v", err)
	}
	if !csr.PublicKey.(*ecdsa.PublicKey).Equal(&id.Key.PublicKey) {
		t.Fatal("the CSR is not for the identity key the Agent stored")
	}
	if sent.HostName != "web-01" || sent.OS != "linux" || sent.Arch != "amd64" || sent.Version != "1.2.3" {
		t.Fatalf("registration said %+v", sent)
	}
	assertNoPrivateKeySent(t, w.stub, id)
	if host, version, ok := w.stub.Agent(id.Cert.Subject.CommonName); !ok || host != "web-01" || version != "1.2.3" {
		t.Fatalf("the platform knows the Agent as %q %q %v", host, version, ok)
	}
}

func TestIdentityIsStoredForTheServiceAccountAlone(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes do not protect files on Windows; the installer sets the directory's ACL")
	}
	w := newWorld(t, platformstub.Options{})
	w.register()
	for path, want := range map[string]os.FileMode{w.cfg.StateDir: 0o700, filepath.Join(w.cfg.StateDir, "identity.pem"): 0o600} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != want {
			t.Fatalf("%s: mode %v, %v; want %v", path, info.Mode().Perm(), err, want)
		}
	}
	// A store others can read is refused, not used.
	if err := os.Chmod(filepath.Join(w.cfg.StateDir, "identity.pem"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := (identity.Store{Dir: w.cfg.StateDir}).Load(); err == nil {
		t.Fatal("a key readable by others was loaded")
	}
}

func TestRegistrationWithAnUnknownOrUsedTokenIsRefusedAndStoresNothing(t *testing.T) {
	w := newWorld(t, platformstub.Options{})
	err := agent.Register(context.Background(), w.cfg, w.stub.URL(), "agt_nope", "web-01")
	if !platform.Rejected(errors.Unwrap(err)) && !platform.Rejected(err) {
		t.Fatalf("expected the platform's refusal, got %v", err)
	}
	if _, _, err := (identity.Store{Dir: w.cfg.StateDir}).Load(); !errors.Is(err, identity.ErrNotRegistered) {
		t.Fatalf("an identity was stored: %v", err)
	}
	w.register()
	if err := agent.Register(context.Background(), w.cfg, w.stub.URL(), "agt_good", "web-02"); err == nil {
		t.Fatal("a token registered a second Agent")
	}
}

func TestTheAgentSpeaksOnlyHTTPS(t *testing.T) {
	w := newWorld(t, platformstub.Options{})
	err := agent.Register(context.Background(), w.cfg, strings.Replace(w.stub.URL(), "https://", "http://", 1), "agt_good", "web-01")
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("expected a refusal to speak in the clear, got %v", err)
	}
	if n := len(w.stub.Requests()); n != 0 {
		t.Fatalf("the Agent connected anyway: %d requests", n)
	}
}

func TestAgentPollsWithItsIdentityCertificateAndReportsItsVersion(t *testing.T) {
	w := newWorld(t, platformstub.Options{PollAfterSeconds: 30})
	w.register()
	id := w.loadIdentity()

	if err := w.runUntil(func() bool { return count(w.stub.Calls(), poll) >= 3 }); err != nil {
		t.Fatal(err)
	}
	polls := 0
	for _, r := range w.stub.Requests() {
		if r.Path != poll {
			continue
		}
		polls++
		if r.ClientCertificate != serialOf(id.Cert) {
			t.Fatalf("poll presented certificate %q, not the Agent's identity %q", r.ClientCertificate, serialOf(id.Cert))
		}
		var body struct{ Version string }
		decodeJSON(t, r.Body, &body)
		if body.Version != "1.2.3" {
			t.Fatalf("poll reported version %q", body.Version)
		}
	}
	// Between polls it waits as the platform said.
	for _, d := range w.clock.Sleeps() {
		if d != 30*time.Second {
			t.Fatalf("slept %v between polls, not 30s", d)
		}
	}
	if _, version, _ := w.stub.Agent(id.Cert.Subject.CommonName); version != "1.2.3" {
		t.Fatalf("the platform has version %q", version)
	}
}

func TestAnAgentThatIsNotRegisteredDoesNotRun(t *testing.T) {
	w := newWorld(t, platformstub.Options{})
	if err := agent.Run(context.Background(), w.cfg); !errors.Is(err, identity.ErrNotRegistered) {
		t.Fatalf("got %v", err)
	}
	if n := len(w.stub.Requests()); n != 0 {
		t.Fatalf("%d requests from an Agent that is not registered", n)
	}
}

func TestIdentityRotatesBeforeItEndsWithANewKeyThatNeverLeavesTheHost(t *testing.T) {
	w := newWorld(t, platformstub.Options{IdentityLife: 30 * 24 * time.Hour})
	w.register()
	before := w.loadIdentity()

	// Not yet: with more than a third of its life left, it is not rotated.
	w.clock.Advance(19 * 24 * time.Hour)
	if err := w.runUntil(func() bool { return count(w.stub.Calls(), poll) >= 2 }); err != nil {
		t.Fatal(err)
	}
	if n := count(w.stub.Calls(), rotation); n != 0 {
		t.Fatalf("rotated %d times with two thirds of its life left", n)
	}

	// Past two thirds of its life.
	w.clock.Advance(2 * 24 * time.Hour)
	polled := count(w.stub.Calls(), poll)
	if err := w.runUntil(func() bool { return count(w.stub.Calls(), poll) >= polled+3 }); err != nil {
		t.Fatal(err)
	}
	if n := count(w.stub.Calls(), rotation); n != 1 {
		t.Fatalf("rotated %d times, want once: %v", n, w.stub.Calls())
	}

	after := w.loadIdentity()
	if serialOf(after.Cert) == serialOf(before.Cert) || after.Key.Equal(before.Key) {
		t.Fatal("the stored identity is not a new key with a new certificate")
	}
	if !after.Cert.NotAfter.After(before.Cert.NotAfter) {
		t.Fatal("the new certificate does not last longer")
	}
	// The rotation was asked for with the old certificate and the polls after it use the new one.
	rotated := false
	for _, r := range w.stub.Requests()[1:] {
		switch {
		case r.Path == rotation:
			rotated = true
			if r.ClientCertificate != serialOf(before.Cert) {
				t.Fatalf("rotation presented %q, not the identity it replaces", r.ClientCertificate)
			}
		case r.Path == poll && rotated && r.ClientCertificate != serialOf(after.Cert):
			t.Fatalf("a poll after the rotation presented %q, not the new identity", r.ClientCertificate)
		}
	}
	assertNoPrivateKeySent(t, w.stub, before)
	assertNoPrivateKeySent(t, w.stub, after)
}

func TestARotationThatFailsLeavesTheIdentityAloneAndIsRetriedWhileTheAgentKeepsPolling(t *testing.T) {
	w := newWorld(t, platformstub.Options{})
	w.register()
	before := w.loadIdentity()
	w.clock.Advance(25 * 24 * time.Hour)
	w.stub.SetRotationFailing(true)

	if err := w.runUntil(func() bool { return count(w.stub.Calls(), rotation) >= 3 }); err != nil {
		t.Fatal(err)
	}
	if n := count(w.stub.Calls(), poll); n < 3 {
		t.Fatalf("the Agent stopped polling while its rotation failed: %d polls", n)
	}
	if serialOf(w.loadIdentity().Cert) != serialOf(before.Cert) {
		t.Fatal("a failed rotation changed the stored identity")
	}

	w.stub.SetRotationFailing(false)
	rotations := count(w.stub.Calls(), rotation)
	if err := w.runUntil(func() bool { return count(w.stub.Calls(), rotation) > rotations }); err != nil {
		t.Fatal(err)
	}
	if serialOf(w.loadIdentity().Cert) == serialOf(before.Cert) {
		t.Fatal("the rotation was not retried to success")
	}
}

func TestAPlatformThatIsDownIsWaitedForWithGrowingPausesAndTheAgentResumes(t *testing.T) {
	w := newWorld(t, platformstub.Options{PollAfterSeconds: 30})
	w.register()
	before := w.loadIdentity()
	w.stub.SetDown(true)
	w.clock.afterEach = nil

	// Six failed attempts, then the platform is back.
	err := w.runUntil(func() bool {
		if len(w.clock.Sleeps()) == 6 {
			w.stub.SetDown(false)
		}
		return count(w.stub.Calls(), poll) >= 9
	})
	if err != nil {
		t.Fatal(err)
	}
	sleeps := w.clock.Sleeps()
	// 1s, 2s, 4s, 8s, 8s, 8s (BackoffMax), each with up to a fifth taken off; then the platform's own 30s once it answers.
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 8 * time.Second, 8 * time.Second}
	for i, d := range want {
		if sleeps[i] > d || sleeps[i] < d*8/10 {
			t.Fatalf("pause %d was %v, want between %v and %v: %v", i, sleeps[i], d*8/10, d, sleeps)
		}
	}
	for _, d := range sleeps[len(want):] {
		if d != 30*time.Second {
			t.Fatalf("after the platform came back it paused %v: %v", d, sleeps)
		}
	}
	if n := count(w.stub.Calls(), registration); n != 1 {
		t.Fatalf("the Agent registered again: %d registrations", n)
	}
	if serialOf(w.loadIdentity().Cert) != serialOf(before.Cert) {
		t.Fatal("an outage cost the Agent its identity")
	}
}

func TestAnUnreachablePlatformIsRetriedAndStoppingTheAgentIsNotAnError(t *testing.T) {
	w := newWorld(t, platformstub.Options{})
	w.register()
	w.stub.Close()

	if err := w.runUntil(func() bool { return len(w.clock.Sleeps()) >= 4 }); err != nil {
		t.Fatalf("an Agent that is stopped returned %v", err)
	}
	if n := len(w.clock.Sleeps()); n < 4 {
		t.Fatalf("it gave up after %d attempts", n)
	}
}

func TestAnAgentThePlatformHasRevokedStopsInsteadOfRetryingForever(t *testing.T) {
	w := newWorld(t, platformstub.Options{})
	w.register()
	w.stub.Revoke(w.loadIdentity().Cert.Subject.CommonName)

	err := w.runUntil(func() bool { return false })
	if !errors.Is(err, agent.ErrIdentityRejected) {
		t.Fatalf("got %v, want the identity to be rejected", err)
	}
	if n := count(w.stub.Calls(), poll); n != 1 {
		t.Fatalf("polled %d times after being refused", n)
	}
}

func TestAnIdentityThatEndedWhileTheAgentWasAwayIsRejected(t *testing.T) {
	w := newWorld(t, platformstub.Options{IdentityLife: 24 * time.Hour})
	w.register()
	w.clock.Advance(48 * time.Hour)
	if err := w.runUntil(func() bool { return false }); !errors.Is(err, agent.ErrIdentityRejected) {
		t.Fatalf("got %v", err)
	}
}

// assertNoPrivateKeySent fails if anything the platform was sent holds the private key, in any encoding the Agent could have used.
func assertNoPrivateKeySent(t *testing.T, stub *platformstub.Stub, id *identity.Identity) {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(id.Key)
	if err != nil {
		t.Fatal(err)
	}
	ec, _ := x509.MarshalECPrivateKey(id.Key)
	d := id.Key.D.Bytes()
	secrets := map[string][]byte{
		"the PKCS#8 key": der, "the SEC1 key": ec,
		"its base64": []byte(base64.StdEncoding.EncodeToString(der)), "its base64url": []byte(base64.RawURLEncoding.EncodeToString(d)),
		"the scalar in hex": []byte(hex.EncodeToString(d)), "the scalar in base64": []byte(base64.StdEncoding.EncodeToString(d)), "a PEM key": []byte("PRIVATE KEY"),
	}
	for _, r := range stub.Requests() {
		for what, secret := range secrets {
			if bytes.Contains(r.Body, secret) {
				t.Fatalf("a request to %s contains %s", r.Path, what)
			}
		}
	}
}
