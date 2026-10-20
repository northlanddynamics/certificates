// Package deploy carries out a Deployment on the Agent: it checks what it was given (the Certificate is the one named, its
// key is here, the script is the one whose hash the platform audited: ADR 0004), puts the Certificate's files where the
// script can read them, runs the Bash or PowerShell script with their paths and the Managed Certificate's identifiers in its
// environment with the Deployment's parameter values, and reports how it went. A script that fails its checks is not run.
package deploy

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"certificate-platform/agent/internal/keystore"
)

// OutputLimit is how much of a script's output is reported: the platform keeps no more.
const OutputLimit = 32 * 1024

// DefaultTimeout is how long a script may run before it is stopped.
const DefaultTimeout = 10 * time.Minute

// ParameterPrefix is put before each parameter's name to make the variable the script reads it from.
const ParameterPrefix = "DEPLOY_PARAM_"

// parameterName is the form a parameter's name takes, so that no name can reach another variable or break the environment.
var parameterName = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// Work is what a `deployment.run` work item carries.
type Work struct {
	DeploymentID         string   `json:"deploymentId"`
	ManagedCertificateID string   `json:"managedCertificateId"`
	Names                []string `json:"names"`
	Certificate          struct {
		Fingerprint string `json:"fingerprint"`
		NotAfter    string `json:"notAfter"`
		ChainPEM    string `json:"chainPem"`
	} `json:"certificate"`
	Script struct {
		Interpreter string `json:"interpreter"`
		Hash        string `json:"hash"`
		Content     string `json:"content"`
	} `json:"script"`
	// Parameters are the Deployment's values by name; an unset optional parameter is not among them.
	Parameters map[string]string `json:"parameters"`
}

// Result is how a run went. ExitCode is nil when the script was not started, and then Output says why.
type Result struct {
	StartedAt, FinishedAt time.Time
	ExitCode              *int
	Output                string
	OutputTruncated       bool
}

// OK is whether the script ran and exited with 0.
func (r Result) OK() bool { return r.ExitCode != nil && *r.ExitCode == 0 }

// Runner runs Deployments.
type Runner struct {
	// Keys holds the private keys, and StateDir is where the Certificate files and the script are put.
	Keys     keystore.Store
	StateDir string
	Now      func() time.Time
	// Timeout stops a script that has not ended; DefaultTimeout when zero.
	Timeout time.Duration
}

func notRun(now time.Time, format string, args ...any) Result {
	return Result{StartedAt: now, FinishedAt: now, Output: fmt.Sprintf(format, args...)}
}

// Run checks the work and, if it is sound, runs the script.
func (r Runner) Run(ctx context.Context, w Work) Result {
	now := r.Now()
	sum := sha256.Sum256([]byte(w.Script.Content))
	if hex.EncodeToString(sum[:]) != strings.ToLower(w.Script.Hash) {
		return notRun(now, "the script does not match its hash, so it was not run")
	}
	certs, leaf, err := parseChain(w.Certificate.ChainPEM)
	if err != nil {
		return notRun(now, "the Certificate cannot be used, so the script was not run: %v", err)
	}
	fingerprint := sha256.Sum256(leaf.Raw)
	if hex.EncodeToString(fingerprint[:]) != strings.ToLower(w.Certificate.Fingerprint) {
		return notRun(now, "the Certificate is not the one named (its fingerprint differs), so the script was not run")
	}
	keyFile, err := r.Keys.KeyFile(w.ManagedCertificateID, leaf)
	if err != nil {
		return notRun(now, "the key for this Certificate is not available on this Agent, so the script was not run: %v", err)
	}
	parameters, err := parameterEnv(w.Parameters)
	if err != nil {
		return notRun(now, "%v, so the script was not run", err)
	}
	files, err := r.writeCertificate(w.ManagedCertificateID, certs)
	if err != nil {
		return notRun(now, "the Certificate's files could not be written, so the script was not run: %v", err)
	}
	script, cleanup, err := r.writeScript(w.Script.Interpreter, w.Script.Content)
	if err != nil {
		return notRun(now, "the script could not be prepared, so it was not run: %v", err)
	}
	defer cleanup()
	command, err := command(w.Script.Interpreter, script)
	if err != nil {
		return notRun(now, "%v", err)
	}

	timeout := r.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, command[0], command[1:]...)
	cmd.Dir = filepath.Dir(files.leaf)
	cmd.Env = append(os.Environ(),
		"CERT_KEY_FILE="+keyFile,
		"CERT_LEAF_FILE="+files.leaf,
		"CERT_CHAIN_FILE="+files.chain,
		"CERT_FULLCHAIN_FILE="+files.fullChain,
		"CERT_MANAGED_CERTIFICATE_ID="+w.ManagedCertificateID,
		"CERT_DEPLOYMENT_ID="+w.DeploymentID,
		"CERT_FINGERPRINT="+w.Certificate.Fingerprint,
		"CERT_NAMES="+strings.Join(w.Names, ","),
		"CERT_NOT_AFTER="+w.Certificate.NotAfter,
	)
	// After the inherited environment, so that a value wins over an Agent variable of the same name.
	cmd.Env = append(cmd.Env, parameters...)
	// One writer for both, so that the output is in the order it was written; it keeps the first OutputLimit bytes.
	out := &limited{limit: OutputLimit}
	cmd.Stdout, cmd.Stderr = out, out
	cmd.WaitDelay = 5 * time.Second
	setProcessGroup(cmd)

	started := r.Now()
	runErr := cmd.Run()
	result := Result{StartedAt: started, FinishedAt: r.Now()}
	var exit *exec.ExitError
	switch {
	case errors.Is(runCtx.Err(), context.DeadlineExceeded):
		out.addNote(fmt.Sprintf("\n[the script was stopped after %s]\n", timeout))
		code := -1
		result.ExitCode = &code
	case errors.As(runErr, &exit):
		code := exit.ExitCode()
		result.ExitCode = &code
	case runErr != nil:
		// It could not be started (no such interpreter), or its output could not be read.
		result.Output = fmt.Sprintf("the script could not be run: %v", runErr)
		return result
	default:
		code := 0
		result.ExitCode = &code
	}
	result.Output, result.OutputTruncated = out.result()
	return result
}

// parameterEnv is the parameters as environment entries, in the order of their names, or why one cannot be given.
func parameterEnv(values map[string]string) ([]string, error) {
	names := slices.Sorted(maps.Keys(values))
	env := make([]string, 0, len(names))
	for _, name := range names {
		if !parameterName.MatchString(name) {
			return nil, fmt.Errorf("the parameter name %q is not one a script can be given", name)
		}
		env = append(env, ParameterPrefix+name+"="+values[name])
	}
	return env, nil
}

func parseChain(chainPEM string) (all []*pem.Block, leaf *x509.Certificate, err error) {
	for rest := []byte(chainPEM); ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			all = append(all, block)
		}
	}
	if len(all) == 0 {
		return nil, nil, errors.New("it holds no certificate")
	}
	leaf, err = x509.ParseCertificate(all[0].Bytes)
	return all, leaf, err
}

type certificateFiles struct{ leaf, chain, fullChain string }

// writeCertificate puts the leaf, the intermediates and both together in a directory of the Managed Certificate's own,
// replacing what an earlier run left.
func (r Runner) writeCertificate(managedCertificateID string, blocks []*pem.Block) (certificateFiles, error) {
	dir := filepath.Join(r.StateDir, "deployments", managedCertificateID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return certificateFiles{}, err
	}
	encode := func(bs []*pem.Block) []byte {
		var out []byte
		for _, b := range bs {
			out = append(out, pem.EncodeToMemory(b)...)
		}
		return out
	}
	files := certificateFiles{leaf: filepath.Join(dir, "leaf.pem"), chain: filepath.Join(dir, "chain.pem"), fullChain: filepath.Join(dir, "fullchain.pem")}
	for path, data := range map[string][]byte{files.leaf: encode(blocks[:1]), files.chain: encode(blocks[1:]), files.fullChain: encode(blocks)} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return certificateFiles{}, err
		}
	}
	return files, nil
}

// writeScript puts the script in a file that only this user can read, to be run from.
func (r Runner) writeScript(interpreter, content string) (path string, cleanup func(), err error) {
	dir := filepath.Join(r.StateDir, "scripts")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", nil, err
	}
	extension := ".sh"
	if interpreter == "powershell" {
		extension = ".ps1"
	}
	file, err := os.CreateTemp(dir, "deployment-*"+extension)
	if err != nil {
		return "", nil, err
	}
	cleanup = func() { os.Remove(file.Name()) }
	if _, err := file.WriteString(content); err != nil {
		file.Close()
		cleanup()
		return "", nil, err
	}
	if err := file.Close(); err != nil {
		cleanup()
		return "", nil, err
	}
	return file.Name(), cleanup, nil
}

func command(interpreter, script string) ([]string, error) {
	switch interpreter {
	case "bash":
		return []string{"bash", script}, nil
	case "powershell":
		// Windows PowerShell on Windows, PowerShell (pwsh) elsewhere.
		shell := "pwsh"
		if runtime.GOOS == "windows" {
			shell = "powershell.exe"
		}
		return []string{shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script}, nil
	}
	return nil, fmt.Errorf("the interpreter %q is not one this Agent runs, so the script was not run", interpreter)
}

// limited is a writer that keeps the first `limit` bytes written to it and counts that it dropped the rest.
type limited struct {
	mu      sync.Mutex
	limit   int
	buf     []byte
	dropped bool
}

func (l *limited) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if room := l.limit - len(l.buf); room >= len(p) {
		l.buf = append(l.buf, p...)
	} else {
		if room > 0 {
			l.buf = append(l.buf, p[:room]...)
		}
		l.dropped = true
	}
	return len(p), nil
}

// addNote adds a note of the Agent's own, which is kept even when the script filled the limit.
func (l *limited) addNote(note string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.buf)+len(note) > l.limit {
		l.buf = l.buf[:max(l.limit-len(note), 0)]
		l.dropped = true
	}
	l.buf = append(l.buf, note...)
}

// result is the output as text the platform can hold: whole characters only, whatever the script wrote.
func (l *limited) result() (string, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	text := strings.ToValidUTF8(string(l.buf), "�")
	for len(text) > l.limit {
		_, size := utf8.DecodeLastRuneInString(text)
		text = text[:len(text)-size]
	}
	return text, l.dropped
}
