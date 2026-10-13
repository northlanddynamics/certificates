// Seam B: the Agent at its process boundary, run against a stub of the platform built from the platform's own contract
// (internal/platformstub), over real TLS, authenticating with a bearer credential (ADR 0006). Time is a clock the tests move,
// so rotating a credential that lasts 30 days, or waiting out a platform that is down, takes no time.
package agent_test

import (
	"context"
	"crypto/x509"
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
	"certificate-platform/agent/internal/credential"
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

func (w *world) loadRecord() credential.Record {
	w.t.Helper()
	record, err := (credential.Store{Dir: w.cfg.StateDir}).Load()
	if err != nil {
		w.t.Fatal(err)
	}
	return record
}

// acceptedBy is whether the platform accepts the credential: whether a poll that presents it is answered, not refused.
func (w *world) acceptedBy(value string) bool {
	w.t.Helper()
	client, err := platform.NewClient(w.stub.URL(), platform.Options{RootCAs: w.cfg.RootCAs, Credential: func() string { return value }})
	if err != nil {
		w.t.Fatal(err)
	}
	_, err = client.Poll(context.Background(), "probe")
	if err != nil && !platform.Rejected(err) {
		w.t.Fatal(err)
	}
	return err == nil
}

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
	rotation     = "/api/agent/credential"
)

func TestRegistrationSendsNoKeyAndStoresTheCredentialThePlatformIssued(t *testing.T) {
	w := newWorld(t, platformstub.Options{})
	w.register()

	requests := w.stub.Requests()
	if len(requests) != 1 || requests[0].Path != registration {
		t.Fatalf("expected one registration, got %v", w.stub.Calls())
	}
	if requests[0].Credential != "" {
		t.Fatal("registration presented a credential, which the Agent does not have yet")
	}
	var sent map[string]string
	decodeJSON(t, requests[0].Body, &sent)
	if len(sent) != 5 || sent["token"] != "agt_good" || sent["hostName"] != "web-01" || sent["os"] != "linux" || sent["arch"] != "amd64" || sent["version"] != "1.2.3" {
		t.Fatalf("registration said %v", sent)
	}

	record := w.loadRecord()
	if !strings.HasPrefix(record.Credential, "agk_") || record.PlatformURL != w.stub.URL() {
		t.Fatalf("the stored registration is %v", record)
	}
	if want := record.IssuedAt.Add(30 * 24 * time.Hour); !record.ExpiresAt.Equal(want) {
		t.Fatalf("the credential ends %v, want %v", record.ExpiresAt, want)
	}
	if host, version, ok := w.stub.Agent(record.AgentID); !ok || host != "web-01" || version != "1.2.3" {
		t.Fatalf("the platform knows the Agent as %q %q %v", host, version, ok)
	}
	if !w.acceptedBy(record.Credential) {
		t.Fatal("the platform does not accept the stored credential")
	}
}

func TestTheCredentialIsStoredForTheServiceAccountAlone(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes do not protect files on Windows; the installer sets the directory's ACL")
	}
	w := newWorld(t, platformstub.Options{})
	w.register()
	path := filepath.Join(w.cfg.StateDir, "credential.json")
	for p, want := range map[string]os.FileMode{w.cfg.StateDir: 0o700, path: 0o600} {
		info, err := os.Stat(p)
		if err != nil || info.Mode().Perm() != want {
			t.Fatalf("%s: mode %v, %v; want %v", p, info.Mode().Perm(), err, want)
		}
	}
	// A store others can read is refused, not used.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := (credential.Store{Dir: w.cfg.StateDir}).Load(); err == nil {
		t.Fatal("a credential readable by others was loaded")
	}
	if err := agent.Run(context.Background(), w.cfg); err == nil {
		t.Fatal("the Agent ran on a credential readable by others")
	}
}

func TestRegistrationWithAnUnknownOrUsedTokenIsRefusedAndStoresNothing(t *testing.T) {
	w := newWorld(t, platformstub.Options{})
	err := agent.Register(context.Background(), w.cfg, w.stub.URL(), "agt_nope", "web-01")
	if !platform.Rejected(errors.Unwrap(err)) && !platform.Rejected(err) {
		t.Fatalf("expected the platform's refusal, got %v", err)
	}
	if _, err := (credential.Store{Dir: w.cfg.StateDir}).Load(); !errors.Is(err, credential.ErrNotRegistered) {
		t.Fatalf("a credential was stored: %v", err)
	}
	w.register()
	if err := agent.Register(context.Background(), w.cfg, w.stub.URL(), "agt_good", "web-02"); err == nil {
		t.Fatal("a token registered a second Agent")
	}
}

func TestRegistrationReportsTheOperatingSystemAsThePlatformNamesIt(t *testing.T) {
	for goos, want := range map[string]string{"linux": "linux", "windows": "windows", "darwin": "macos"} {
		if got := agent.PlatformOS(goos); got != want {
			t.Fatalf("%s is reported as %q, not %q", goos, got, want)
		}
	}
	for _, p := range []struct{ os, arch string }{{"macos", "arm64"}, {"macos", "amd64"}, {"windows", "amd64"}, {"linux", "arm64"}} {
		w := newWorld(t, platformstub.Options{})
		w.cfg.OS, w.cfg.Arch = p.os, p.arch
		w.register()
		os, arch := w.stub.AgentPlatform(w.stub.AgentIDs()[0])
		if os != p.os || arch != p.arch {
			t.Fatalf("registered as %s/%s, the platform has %s/%s", p.os, p.arch, os, arch)
		}
	}
	// What the platform has no name for is refused before anything is sent: not Go's own "darwin" either.
	for _, p := range []struct{ os, arch string }{{"darwin", "arm64"}, {"freebsd", "amd64"}, {"linux", "386"}} {
		w := newWorld(t, platformstub.Options{})
		w.stub.AddToken("agt_good")
		w.cfg.OS, w.cfg.Arch = p.os, p.arch
		if err := agent.Register(context.Background(), w.cfg, w.stub.URL(), "agt_good", "web-01"); err == nil {
			t.Fatalf("registered as %s/%s", p.os, p.arch)
		}
		if n := len(w.stub.Requests()); n != 0 {
			t.Fatalf("%d requests for %s/%s", n, p.os, p.arch)
		}
	}
}

func TestTheAgentSpeaksOnlyHTTPSExceptToALoopbackAddress(t *testing.T) {
	w := newWorld(t, platformstub.Options{})
	for _, url := range []string{"http://platform.example", "http://192.0.2.10:3000", "http://[2001:db8::1]", "ftp://localhost"} {
		err := agent.Register(context.Background(), w.cfg, url, "agt_good", "web-01")
		if err == nil || !strings.Contains(err.Error(), "https") {
			t.Fatalf("%s: expected a refusal to speak in the clear, got %v", url, err)
		}
	}
	// The stub's own address, over plain http, is a loopback address, but it speaks TLS, so nothing is exchanged.
	if n := len(w.stub.Requests()); n != 0 {
		t.Fatalf("the Agent connected anyway: %d requests", n)
	}
}

func TestOnLoopbackAnAgentRegistersAndPollsOverPlainHTTP(t *testing.T) {
	c := &clock{now: time.Now().UTC().Truncate(time.Second)}
	stub, err := platformstub.Start(platformstub.Options{Clock: c, PlainHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	defer stub.Close()
	if !strings.HasPrefix(stub.URL(), "http://127.0.0.1:") {
		t.Fatalf("the stub is at %s", stub.URL())
	}
	// No root certificates and no certificate: development needs none.
	cfg := agent.Config{StateDir: filepath.Join(t.TempDir(), "state"), Version: "1.2.3", Clock: c, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), OS: "macos", Arch: "arm64"}
	stub.AddToken("agt_dev")
	if err := agent.Register(context.Background(), cfg, stub.URL(), "agt_dev", "laptop"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.afterEach = func(int) { cancel() }
	if err := agent.Run(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if count(stub.Calls(), poll) != 1 {
		t.Fatalf("calls: %v", stub.Calls())
	}
	if v := stub.ContractViolations(); len(v) != 0 {
		t.Fatalf("%v", v)
	}
}

func TestAgentPollsWithItsCredentialAndReportsItsVersion(t *testing.T) {
	w := newWorld(t, platformstub.Options{PollAfterSeconds: 30})
	w.register()
	record := w.loadRecord()

	if err := w.runUntil(func() bool { return count(w.stub.Calls(), poll) >= 3 }); err != nil {
		t.Fatal(err)
	}
	for _, r := range w.stub.Requests() {
		if r.Path != poll {
			continue
		}
		if r.Credential != record.Credential {
			t.Fatal("a poll did not present the Agent's credential")
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
	if _, version, _ := w.stub.Agent(record.AgentID); version != "1.2.3" {
		t.Fatalf("the platform has version %q", version)
	}
}

func TestAnAgentThatIsNotRegisteredDoesNotRun(t *testing.T) {
	w := newWorld(t, platformstub.Options{})
	if err := agent.Run(context.Background(), w.cfg); !errors.Is(err, credential.ErrNotRegistered) {
		t.Fatalf("got %v", err)
	}
	if n := len(w.stub.Requests()); n != 0 {
		t.Fatalf("%d requests from an Agent that is not registered", n)
	}
}

func TestTheCredentialRotatesBeforeItEndsAndTheOldOneStopsWorkingOnceTheNewIsUsed(t *testing.T) {
	w := newWorld(t, platformstub.Options{CredentialLife: 30 * 24 * time.Hour})
	w.register()
	before := w.loadRecord()

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

	after := w.loadRecord()
	if after.Credential == before.Credential || !strings.HasPrefix(after.Credential, "agk_") {
		t.Fatal("the stored credential is not a new one")
	}
	if !after.ExpiresAt.After(before.ExpiresAt) || after.AgentID != before.AgentID || after.PlatformURL != before.PlatformURL {
		t.Fatalf("the new registration is %v, the old %v", after, before)
	}
	// The rotation was asked for with the old credential and the polls after it use the new one.
	rotated := false
	for _, r := range w.stub.Requests()[1:] {
		switch {
		case r.Path == rotation:
			rotated = true
			if r.Credential != before.Credential {
				t.Fatal("the rotation did not present the credential it replaces")
			}
		case r.Path == poll && rotated && r.Credential != after.Credential:
			t.Fatal("a poll after the rotation did not present the new credential")
		}
	}
	if !rotated {
		t.Fatal("no rotation")
	}
	if w.acceptedBy(before.Credential) || !w.acceptedBy(after.Credential) {
		t.Fatal("the platform should accept the new credential and no longer the old")
	}
}

func TestARotationThatFailsLeavesTheCredentialAloneAndIsRetriedWhileTheAgentKeepsPolling(t *testing.T) {
	w := newWorld(t, platformstub.Options{})
	w.register()
	before := w.loadRecord()
	w.clock.Advance(25 * 24 * time.Hour)
	w.stub.SetRotationFailing(true)

	if err := w.runUntil(func() bool { return count(w.stub.Calls(), rotation) >= 3 }); err != nil {
		t.Fatal(err)
	}
	if n := count(w.stub.Calls(), poll); n < 3 {
		t.Fatalf("the Agent stopped polling while its rotation failed: %d polls", n)
	}
	if w.loadRecord().Credential != before.Credential {
		t.Fatal("a failed rotation changed the stored credential")
	}

	w.stub.SetRotationFailing(false)
	rotations := count(w.stub.Calls(), rotation)
	if err := w.runUntil(func() bool { return count(w.stub.Calls(), rotation) > rotations }); err != nil {
		t.Fatal(err)
	}
	if w.loadRecord().Credential == before.Credential {
		t.Fatal("the rotation was not retried to success")
	}
}

// The platform rotated, but the answer never arrived: the Agent has only the old credential, which the platform still accepts
// until a new one is used, so it asks again with the old one and carries on.
func TestARotationWhoseAnswerWasLostIsAskedAgainWithTheOldCredential(t *testing.T) {
	w := newWorld(t, platformstub.Options{})
	w.register()
	before := w.loadRecord()
	w.clock.Advance(25 * 24 * time.Hour)
	w.stub.SetRotationAnswerLost(true)

	if err := w.runUntil(func() bool { return count(w.stub.Calls(), rotation) >= 3 }); err != nil {
		t.Fatalf("an Agent whose rotation was lost returned %v", err)
	}
	if w.loadRecord().Credential != before.Credential {
		t.Fatal("the stored credential changed without an answer")
	}
	for _, r := range w.stub.Requests() {
		if r.Credential != "" && r.Credential != before.Credential {
			t.Fatal("the Agent presented a credential it was never given")
		}
	}

	w.stub.SetRotationAnswerLost(false)
	rotations := count(w.stub.Calls(), rotation)
	polled := count(w.stub.Calls(), poll)
	if err := w.runUntil(func() bool { return count(w.stub.Calls(), poll) >= polled+3 }); err != nil {
		t.Fatalf("got %v", err)
	}
	if n := count(w.stub.Calls(), rotation); n != rotations+1 {
		t.Fatalf("rotated %d more times, want once", n-rotations)
	}
	after := w.loadRecord()
	if after.Credential == before.Credential || !w.acceptedBy(after.Credential) || w.acceptedBy(before.Credential) {
		t.Fatal("the Agent did not end up on the credential the platform issued last")
	}
}

// The new credential is stored before it is used: one that cannot be stored is not used, and the Agent stays on the old one,
// which the platform still accepts, instead of being locked out by a credential it would lose at a restart.
func TestACredentialThatCannotBeStoredIsNotUsed(t *testing.T) {
	w := newWorld(t, platformstub.Options{})
	w.register()
	before := w.loadRecord()
	path := filepath.Join(w.cfg.StateDir, "credential.json")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.clock.afterEach = func(slept int) {
		if slept == 1 {
			// Nothing can be renamed onto a directory, so the Agent can no longer store a credential; and its rotation is due.
			if err := os.Remove(path); err != nil {
				t.Error(err)
			}
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Error(err)
			}
			w.clock.Advance(25 * 24 * time.Hour)
		}
		if count(w.stub.Calls(), poll) >= 5 {
			cancel()
		}
	}
	if err := agent.Run(ctx, w.cfg); err != nil {
		t.Fatalf("got %v", err)
	}
	if n := count(w.stub.Calls(), rotation); n < 2 {
		t.Fatalf("expected the rotation to be tried again, %d tries", n)
	}
	for _, r := range w.stub.Requests() {
		if r.Credential != "" && r.Credential != before.Credential {
			t.Fatal("the Agent used a credential it could not store")
		}
	}
}

func TestAPlatformThatIsDownIsWaitedForWithGrowingPausesAndTheAgentResumes(t *testing.T) {
	w := newWorld(t, platformstub.Options{PollAfterSeconds: 30})
	w.register()
	before := w.loadRecord()
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
	if w.loadRecord().Credential != before.Credential {
		t.Fatal("an outage cost the Agent its credential")
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
	w.stub.Revoke(w.loadRecord().AgentID)

	err := w.runUntil(func() bool { return false })
	if !errors.Is(err, agent.ErrCredentialRejected) {
		t.Fatalf("got %v, want the credential to be rejected", err)
	}
	if n := count(w.stub.Calls(), poll); n != 1 {
		t.Fatalf("polled %d times after being refused", n)
	}
}

func TestACredentialThatEndedWhileTheAgentWasAwayIsRejected(t *testing.T) {
	w := newWorld(t, platformstub.Options{CredentialLife: 24 * time.Hour})
	w.register()
	w.clock.Advance(48 * time.Hour)
	if err := w.runUntil(func() bool { return false }); !errors.Is(err, agent.ErrCredentialRejected) {
		t.Fatalf("got %v", err)
	}
}

// The credential is a secret: whatever the Agent logs, and whatever errors it returns, it is in none of it.
func TestTheCredentialIsNeverLoggedOrReturnedInAnError(t *testing.T) {
	w, logs := relayWorld(t)
	first := w.loadRecord().Credential
	w.clock.Advance(25 * 24 * time.Hour)
	w.stub.SetRotationFailing(true)
	if err := w.runUntil(func() bool { return count(w.stub.Calls(), rotation) >= 2 }); err != nil {
		t.Fatal(err)
	}
	w.stub.SetRotationFailing(false)
	if err := w.runUntil(func() bool { return count(w.stub.Calls(), rotation) >= 3 }); err != nil {
		t.Fatal(err)
	}
	second := w.loadRecord().Credential
	if second == first {
		t.Fatal("no rotation")
	}
	w.stub.Revoke(w.loadRecord().AgentID)
	err := w.runUntil(func() bool { return false })
	if !errors.Is(err, agent.ErrCredentialRejected) {
		t.Fatalf("got %v", err)
	}
	for _, secret := range []string{first, second} {
		if strings.Contains(logs.String(), secret) || strings.Contains(err.Error(), secret) {
			t.Fatal("the Agent logged or returned a credential")
		}
	}
	if !strings.Contains(logs.String(), "rotated the credential") {
		t.Fatalf("the rotation was not logged: %s", logs.String())
	}
}
