package main_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"certificate-platform/agent/internal/platformstub"
)

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// The Agent as a process: built as the release is (with its version set), registered and run from the command line against
// the stub platform.
func TestTheAgentBinaryRegistersAndPollsWithItsCredential(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "agent")
	build := exec.Command("go", "build", "-ldflags", "-X main.version=9.9.9", "-o", binary, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	stub, err := platformstub.Start(platformstub.Options{Clock: realClock{}, PollAfterSeconds: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer stub.Close()
	stub.AddToken("agt_cli")
	caFile := filepath.Join(dir, "platform.pem")
	if err := os.WriteFile(caFile, stub.ServerCertificatePEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "state")
	common := []string{"--state-dir", state, "--ca-file", caFile}

	// The token comes in the environment, not on the command line where other users of the host would see it.
	register := exec.Command(binary, append([]string{"register", "--platform", stub.URL(), "--host-name", "cli-host", "--os", "linux", "--arch", "amd64"}, common...)...)
	register.Env = append(os.Environ(), "AGENT_REGISTRATION_TOKEN=agt_cli")
	if out, err := register.CombinedOutput(); err != nil {
		t.Fatalf("register: %v\n%s", err, out)
	}

	run := exec.Command(binary, append([]string{"run"}, common...)...)
	if err := run.Start(); err != nil {
		t.Fatal(err)
	}
	defer run.Process.Kill()
	deadline := time.Now().Add(20 * time.Second)
	polls := 0
	for time.Now().Before(deadline) && polls < 2 {
		time.Sleep(100 * time.Millisecond)
		polls = 0
		for _, c := range stub.Calls() {
			if c == "/api/agent/poll" {
				polls++
			}
		}
	}
	if polls < 2 {
		t.Fatalf("the Agent polled %d times in 20s: %v", polls, stub.Calls())
	}
	for _, r := range stub.Requests() {
		if r.Path == "/api/agent/poll" && !strings.HasPrefix(r.Credential, "agk_") {
			t.Fatal("a poll without the Agent's credential")
		}
	}
	host, version, _ := stub.Agent(stub.AgentIDs()[0])
	if os, arch := stub.AgentPlatform(stub.AgentIDs()[0]); os != "linux" || arch != "amd64" {
		t.Fatalf("the platform knows the Agent as %s/%s", os, arch)
	}
	if host != "cli-host" || version != "9.9.9" {
		t.Fatalf("the platform knows the Agent as %q running %q", host, version)
	}
	// Stopped by a signal, as a service manager stops it, it ends cleanly.
	if err := run.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	if err := run.Wait(); err != nil {
		t.Fatalf("the Agent did not stop cleanly: %v", err)
	}
	if v := stub.ContractViolations(); len(v) != 0 {
		t.Fatalf("%v", v)
	}
}

// Development: a platform on the same host, over plain HTTP, needs no certificate and no --ca-file, and the Agent reports the
// host's own operating system by default.
func TestTheAgentBinaryRegistersWithALoopbackPlatformOverPlainHTTP(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "agent")
	if out, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	stub, err := platformstub.Start(platformstub.Options{Clock: realClock{}, PlainHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	defer stub.Close()
	stub.AddToken("agt_dev")
	register := exec.Command(binary, "register", "--platform", stub.URL(), "--state-dir", filepath.Join(dir, "state"))
	register.Env = append(os.Environ(), "AGENT_REGISTRATION_TOKEN=agt_dev")
	if out, err := register.CombinedOutput(); err != nil {
		t.Fatalf("register: %v\n%s", err, out)
	}
	want := map[string]string{"darwin": "macos"}[runtime.GOOS]
	if want == "" {
		want = runtime.GOOS
	}
	if os, arch := stub.AgentPlatform(stub.AgentIDs()[0]); os != want || arch != runtime.GOARCH {
		t.Fatalf("the platform knows the Agent as %s/%s, want %s/%s", os, arch, want, runtime.GOARCH)
	}
	if v := stub.ContractViolations(); len(v) != 0 {
		t.Fatalf("%v", v)
	}
}

func TestTheAgentBinaryRefusesAPlatformOverPlainHTTPAndAnUnregisteredRun(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "agent")
	if out, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	register := exec.Command(binary, "register", "--platform", "http://platform.example", "--token", "agt_x", "--state-dir", filepath.Join(dir, "state"))
	out, err := register.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "https") {
		t.Fatalf("register over http: %v\n%s", err, out)
	}
	// Only the platform's names for operating systems: macos, not darwin.
	out, err = exec.Command(binary, "register", "--platform", "https://platform.example", "--token", "agt_x", "--os", "darwin", "--state-dir", filepath.Join(dir, "state")).CombinedOutput()
	if err == nil || !strings.Contains(string(out), "macos") {
		t.Fatalf("register as darwin: %v\n%s", err, out)
	}
	out, err = exec.Command(binary, "run", "--state-dir", filepath.Join(dir, "state")).CombinedOutput()
	if err == nil || !strings.Contains(string(out), "not registered") {
		t.Fatalf("run unregistered: %v\n%s", err, out)
	}
	out, err = exec.Command(binary, "version").CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "0.1.0" {
		t.Fatalf("version: %v %q", err, out)
	}
}
