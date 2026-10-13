// The Agent: software an Organization installs inside its network to act for the platform there. It only ever connects
// outbound to the platform, over HTTPS (plain HTTP only to a loopback address, for development), and authenticates with a
// bearer credential that the platform made for it at registration and that it rotates itself (ADR 0006). It runs on Linux,
// Windows and macOS, on amd64 and arm64.
//
//	agent register --platform https://certs.example.com --token agt_...   once, with a token an Organization Administrator made
//	agent run                                                             then, as a service
//	agent version
package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"certificate-platform/agent/internal/agent"
)

// version is what the Agent reports to the platform, which flags Agents older than the latest. Releases set it with
// -ldflags "-X main.version=...".
var version = "0.1.0"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "agent:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: agent register|run|version")
	}
	command, args := args[0], args[1:]
	if command == "version" {
		fmt.Println(version)
		return nil
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	stateDir := flags.String("state-dir", envOr("AGENT_STATE_DIR", defaultStateDir()), "where the Agent keeps its credential (readable only by its service account)")
	caFile := flags.String("ca-file", os.Getenv("AGENT_CA_FILE"), "extra root certificates (PEM) to trust the platform's TLS certificate with, besides the host's")
	platformURL := flags.String("platform", os.Getenv("AGENT_PLATFORM_URL"), "register: the platform's URL, https (http only for a loopback address such as http://localhost:3000)")
	token := flags.String("token", "", "register: the registration token (or set AGENT_REGISTRATION_TOKEN, which keeps it out of the process list)")
	hostName := flags.String("host-name", "", "register: the name to show for this host (default: its host name)")
	osName := flags.String("os", agent.PlatformOS(runtime.GOOS), "register: the operating system to report (linux, windows or macos); the host's, except to test against a stub")
	arch := flags.String("arch", runtime.GOARCH, "register: the architecture to report (amd64 or arm64); the host's, except to test against a stub")
	if err := flags.Parse(args); err != nil {
		return err
	}
	roots, err := roots(*caFile)
	if err != nil {
		return err
	}
	if command == "register" && *osName != "linux" && *osName != "windows" && *osName != "macos" {
		return fmt.Errorf("--os must be linux, windows or macos, not %q", *osName)
	}
	cfg := agent.Config{StateDir: *stateDir, Version: version, RootCAs: roots, OS: *osName, Arch: *arch, Log: slog.New(slog.NewTextHandler(os.Stderr, nil))}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch command {
	case "register":
		if *platformURL == "" {
			return errors.New("register needs --platform")
		}
		if *token == "" {
			*token = os.Getenv("AGENT_REGISTRATION_TOKEN")
		}
		if *token == "" {
			return errors.New("register needs --token or AGENT_REGISTRATION_TOKEN")
		}
		name := *hostName
		if name == "" {
			if name, err = os.Hostname(); err != nil {
				return err
			}
		}
		return agent.Register(ctx, cfg, *platformURL, *token, name)
	case "run":
		return agent.Run(ctx, cfg)
	default:
		return fmt.Errorf("unknown command %q: usage: agent register|run|version", command)
	}
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func defaultStateDir() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(envOr("ProgramData", `C:\ProgramData`), "CertificateAgent")
	case "darwin":
		return "/Library/Application Support/CertificateAgent"
	}
	return "/var/lib/certificate-agent"
}

// roots is the host's roots, with those in caFile added; nil (the host's roots alone) when there is no caFile.
func roots(caFile string) (*x509.CertPool, error) {
	if caFile == "" {
		return nil, nil
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s holds no certificate", caFile)
	}
	return pool, nil
}
