// Package platformstub is a stand-in for the platform's Agent protocol, for Seam B: the Agent runs against it as against the
// real platform, over real TLS (or plain HTTP on loopback, as in development), authenticating with a bearer credential. It is
// built from the contract (agent/contract/openapi.json): which routes exist, which of them need the Agent's credential, and
// what their requests and responses look like
// are read from it, and every request it receives and every response it sends is validated against it, so an Agent that drifts
// from the contract, and a stub that does, both fail. The behaviour behind the routes is the minimum the Agent's tests need.
package platformstub

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"certificate-platform/agent/contract"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Clock is the time the stub works in: credentials are issued and checked against it.
type Clock interface{ Now() time.Time }

// Request is one call the stub received.
type Request struct {
	Method string
	Path   string
	Body   []byte
	// Credential is the bearer credential presented, empty when there was none.
	Credential string
}

// WorkItem is something the stub asks an Agent to do, as the platform does: its payload is what the Agent is sent.
type WorkItem struct {
	ID      string         `json:"id"`
	Type    string         `json:"type"`
	Payload map[string]any `json:"payload"`
}

// Run is how an Agent reported that a Deployment Script went.
type Run struct {
	StartedAt, FinishedAt string
	// ExitCode is nil when the script was not started.
	ExitCode        *int
	Output          string
	OutputTruncated bool
}

// Result is what an Agent reported of a work item.
type Result struct {
	ID    string
	OK    bool
	Kind  string
	Error string
	// CSR is what an Agent that made a key reported, Run how a Deployment Script went, Discovery what it found at an ADCS
	// CA, Submission what ADCS answered a request with, and Revocation that ADCS revoked a Certificate.
	CSR        string
	Run        *Run
	Discovery  map[string]any
	Submission map[string]any
	Revocation map[string]any
}

// issued is a credential the stub made, with when it ends.
type issued struct {
	value     string
	expiresAt time.Time
}

type agentRecord struct {
	id string
	// current is the latest credential; previous is the one it replaced, accepted until current is first used.
	current  issued
	previous *issued
	revoked  bool
	hostName string
	os, arch string
	version  string
	lastSeen time.Time
}

type operation struct {
	needsCredential bool
	request         *jsonschema.Schema
	responses       map[int]*jsonschema.Schema
}

// Stub is a running stub platform.
type Stub struct {
	clock  Clock
	server *httptest.Server
	ops    map[string]*operation

	mu       sync.Mutex
	tokens   map[string]bool
	agents   map[string]*agentRecord
	requests []Request
	failures []string
	// queued are the work items not yet given to an Agent; given those that were, which wait for a result.
	queued  []WorkItem
	given   map[string]bool
	results []Result
	down    bool
	// rotationFailing makes rotating a credential fail with a 500, before anything is rotated.
	rotationFailing bool
	// rotationAnswerLost makes the stub rotate the credential and then drop the connection, so the Agent never gets the answer.
	rotationAnswerLost bool
	// credentialLife is how long the credentials it issues last.
	credentialLife time.Duration
	pollSeconds    int
	serverCert     tls.Certificate
	serverPEM      []byte
}

// Options are what a test may choose.
type Options struct {
	Clock Clock
	// CredentialLife is how long credentials last; 30 days like the platform's by default.
	CredentialLife time.Duration
	// PlainHTTP serves plain HTTP on a loopback address instead of TLS, as a platform in development is.
	PlainHTTP bool
	// PollAfterSeconds is what polls are told; 30 by default.
	PollAfterSeconds int
}

// Start runs a stub on a local port. Close it when done.
func Start(opts Options) (*Stub, error) {
	s := &Stub{clock: opts.Clock, tokens: map[string]bool{}, agents: map[string]*agentRecord{}, given: map[string]bool{}, credentialLife: opts.CredentialLife, pollSeconds: opts.PollAfterSeconds}
	if s.credentialLife == 0 {
		s.credentialLife = 30 * 24 * time.Hour
	}
	if s.pollSeconds == 0 {
		s.pollSeconds = 30
	}
	if err := s.loadContract(); err != nil {
		return nil, err
	}
	s.server = httptest.NewUnstartedServer(http.HandlerFunc(s.handle))
	if opts.PlainHTTP {
		s.server.Start()
		return s, nil
	}
	if err := s.makeServerCertificate(); err != nil {
		return nil, err
	}
	s.server.TLS = &tls.Config{Certificates: []tls.Certificate{s.serverCert}, MinVersion: tls.VersionTLS12}
	s.server.StartTLS()
	return s, nil
}

func (s *Stub) Close() { s.server.Close() }

// URL is where the stub is served.
func (s *Stub) URL() string { return s.server.URL }

// ServerCertificatePEM is the certificate the stub's TLS server presents, for the Agent to trust it.
func (s *Stub) ServerCertificatePEM() []byte { return s.serverPEM }

// AddToken makes a registration token the stub accepts, once.
func (s *Stub) AddToken(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token] = true
}

// SetDown makes the stub fail every call with a 503, as a platform that is down or unreachable does.
func (s *Stub) SetDown(down bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.down = down
}

// SetRotationFailing makes the stub fail credential rotations (and only those) with a 500, rotating nothing.
func (s *Stub) SetRotationFailing(failing bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rotationFailing = failing
}

// SetRotationAnswerLost makes the stub carry out credential rotations but never deliver the answer: it drops the connection,
// as a network that fails at the wrong moment does.
func (s *Stub) SetRotationAnswerLost(lost bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rotationAnswerLost = lost
}

// Revoke makes the stub refuse the Agent's credential from now on.
func (s *Stub) Revoke(agentID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agents[agentID].revoked = true
}

// Enqueue asks the Agent that next polls to do something, once.
func (s *Stub) Enqueue(item WorkItem) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queued = append(s.queued, item)
}

// Results are the reports on work items received so far, in order.
func (s *Stub) Results() []Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Result(nil), s.results...)
}

// Requests are the calls received so far, in order.
func (s *Stub) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}

// Calls are the paths of the requests received, in order.
func (s *Stub) Calls() []string {
	var paths []string
	for _, r := range s.Requests() {
		paths = append(paths, r.Path)
	}
	return paths
}

// ContractViolations are the ways the Agent's requests, or the stub's own answers, did not conform to the contract.
func (s *Stub) ContractViolations() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.failures...)
}

// Agent is what the stub knows of a registered Agent.
func (s *Stub) Agent(id string) (hostName, version string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.agents[id]
	if !ok {
		return "", "", false
	}
	return a.hostName, a.version, true
}

// AgentPlatform is the operating system and architecture an Agent registered as running on.
func (s *Stub) AgentPlatform(id string) (os, arch string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.agents[id]; ok {
		return a.os, a.arch
	}
	return "", ""
}

// AgentIDs are the Agents registered so far.
func (s *Stub) AgentIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var ids []string
	for id := range s.agents {
		ids = append(ids, id)
	}
	return ids
}

func (s *Stub) loadContract() error {
	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(contract.OpenAPI, &doc); err != nil {
		return fmt.Errorf("the contract cannot be read: %w", err)
	}
	parsed, err := jsonschema.UnmarshalJSON(bytes.NewReader(contract.OpenAPI))
	if err != nil {
		return err
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("contract.json", parsed); err != nil {
		return err
	}
	pointer := func(parts ...string) string {
		escaped := make([]string, len(parts))
		for i, p := range parts {
			escaped[i] = strings.NewReplacer("~", "~0", "/", "~1").Replace(p)
		}
		return "contract.json#/" + strings.Join(escaped, "/")
	}
	s.ops = map[string]*operation{}
	for path, methods := range doc.Paths {
		for method, raw := range methods {
			compiled := &operation{responses: map[int]*jsonschema.Schema{}}
			var detail struct {
				Security    []map[string]any `json:"security"`
				RequestBody *struct {
					Content map[string]json.RawMessage `json:"content"`
				} `json:"requestBody"`
				Responses map[string]struct {
					Content map[string]json.RawMessage `json:"content"`
				} `json:"responses"`
			}
			if err := json.Unmarshal(raw, &detail); err != nil {
				return err
			}
			compiled.needsCredential = len(detail.Security) > 0
			if detail.RequestBody != nil && detail.RequestBody.Content["application/json"] != nil {
				if compiled.request, err = compiler.Compile(pointer("paths", path, method, "requestBody", "content", "application/json", "schema")); err != nil {
					return fmt.Errorf("the request schema of %s %s: %w", method, path, err)
				}
			}
			for status, response := range detail.Responses {
				if response.Content["application/json"] == nil {
					continue
				}
				var code int
				if _, err := fmt.Sscanf(status, "%d", &code); err != nil {
					continue
				}
				if compiled.responses[code], err = compiler.Compile(pointer("paths", path, method, "responses", status, "content", "application/json", "schema")); err != nil {
					return fmt.Errorf("the response schema of %s %s %s: %w", method, path, status, err)
				}
			}
			s.ops[strings.ToUpper(method)+" "+path] = compiled
		}
	}
	return nil
}

func (s *Stub) makeServerCertificate() error {
	now := s.clock.Now()
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "stub platform"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(20 * 365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, serverTemplate, &serverKey.PublicKey, serverKey)
	if err != nil {
		return err
	}
	s.serverCert = tls.Certificate{Certificate: [][]byte{serverDER}, PrivateKey: serverKey}
	s.serverPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})
	return nil
}

func (s *Stub) violation(format string, args ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures = append(s.failures, fmt.Sprintf(format, args...))
}

func (s *Stub) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	bearer := bearerOf(r)
	s.mu.Lock()
	s.requests = append(s.requests, Request{Method: r.Method, Path: r.URL.Path, Body: body, Credential: bearer})
	down := s.down
	s.mu.Unlock()

	if down {
		s.reply(w, r, 503, map[string]string{"error": "the platform is down"}, nil)
		return
	}
	op, template := s.operation(r.Method, r.URL.Path)
	if op == nil {
		s.violation("%s %s is not in the contract", r.Method, r.URL.Path)
		s.reply(w, r, 404, map[string]string{"error": "not found"}, nil)
		return
	}
	var request any
	if op.request != nil {
		var err error
		if request, err = jsonschema.UnmarshalJSON(bytes.NewReader(body)); err != nil {
			s.violation("%s %s: the request body is not JSON", r.Method, r.URL.Path)
			s.reply(w, r, 400, map[string]string{"error": "not JSON"}, nil)
			return
		}
		if err := op.request.Validate(request); err != nil {
			s.violation("%s %s: the request does not conform to the contract: %v", r.Method, r.URL.Path, err)
			s.reply(w, r, 400, map[string]string{"error": "the request does not conform to the contract"}, nil)
			return
		}
	}
	var agent *agentRecord
	if op.needsCredential {
		if agent = s.authenticate(bearer); agent == nil {
			s.reply(w, r, 401, map[string]string{"error": "the Agent's credential is not accepted"}, op)
			return
		}
	}
	var payload map[string]any
	_ = json.Unmarshal(body, &payload)
	switch template {
	case "/api/agent/registration":
		status, answer := s.register(payload)
		s.reply(w, r, status, answer, op)
	case "/api/agent/poll":
		s.mu.Lock()
		agent.version, _ = payload["version"].(string)
		agent.lastSeen = s.clock.Now()
		items := []WorkItem{}
		for _, item := range s.queued {
			s.given[item.ID] = true
			items = append(items, item)
		}
		s.queued = nil
		s.mu.Unlock()
		s.reply(w, r, 200, map[string]any{"items": items, "pollAfterSeconds": s.pollSeconds}, op)
	case "/api/agent/work-items/{id}/result":
		status, answer := s.report(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/agent/work-items/"), "/result"), payload)
		s.reply(w, r, status, answer, op)
	case "/api/agent/credential":
		s.mu.Lock()
		failing, lost := s.rotationFailing, s.rotationAnswerLost
		s.mu.Unlock()
		if failing {
			s.reply(w, r, 500, map[string]string{"error": "internal error"}, nil)
			return
		}
		status, answer := s.rotate(agent, bearer)
		if lost {
			s.dropConnection(w)
			return
		}
		s.reply(w, r, status, answer, op)
	default:
		s.reply(w, r, 501, map[string]string{"error": "the stub does not implement this route"}, nil)
	}
}

// operation is the contract's operation for the call, whose path may have parameters (`/work-items/{id}/result`), and the path as the contract writes it.
func (s *Stub) operation(method, path string) (*operation, string) {
	if op := s.ops[method+" "+path]; op != nil {
		return op, path
	}
	actual := strings.Split(path, "/")
	for key, op := range s.ops {
		verb, template, _ := strings.Cut(key, " ")
		parts := strings.Split(template, "/")
		if verb != method || len(parts) != len(actual) {
			continue
		}
		matches := true
		for i, part := range parts {
			if !(strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}")) && part != actual[i] {
				matches = false
				break
			}
		}
		if matches {
			return op, template
		}
	}
	return nil, path
}

// report is the platform taking an Agent's report: of an item it was given, once.
func (s *Stub) report(id string, payload map[string]any) (int, any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, known := s.given[id]; !known {
		return 404, map[string]string{"error": "work item not found"}
	}
	if !s.given[id] {
		return 409, map[string]string{"error": "the work item is not waiting for a result"}
	}
	s.given[id] = false
	result := Result{ID: id}
	result.OK, _ = payload["ok"].(bool)
	result.Kind, _ = payload["kind"].(string)
	result.Error, _ = payload["error"].(string)
	result.CSR, _ = payload["csr"].(string)
	result.Discovery, _ = payload["discovery"].(map[string]any)
	result.Submission, _ = payload["submission"].(map[string]any)
	result.Revocation, _ = payload["revocation"].(map[string]any)
	if run, ok := payload["run"].(map[string]any); ok {
		reported := &Run{}
		reported.StartedAt, _ = run["startedAt"].(string)
		reported.FinishedAt, _ = run["finishedAt"].(string)
		reported.Output, _ = run["output"].(string)
		reported.OutputTruncated, _ = run["outputTruncated"].(bool)
		if code, ok := run["exitCode"].(float64); ok {
			n := int(code)
			reported.ExitCode = &n
		}
		result.Run = reported
	}
	s.results = append(s.results, result)
	return 200, map[string]any{"received": true}
}

func bearerOf(r *http.Request) string {
	scheme, credential, _ := strings.Cut(r.Header.Get("authorization"), " ")
	if !strings.EqualFold(scheme, "bearer") {
		return ""
	}
	return strings.TrimSpace(credential)
}

// authenticate is the platform's check of a bearer credential: it is an Agent's current credential, or the one it replaced
// while the new one has not been used yet, it has not ended, and the Agent is not revoked. Using the current credential
// retires the one it replaced.
func (s *Stub) authenticate(bearer string) *agentRecord {
	if !strings.HasPrefix(bearer, "agk_") {
		return nil
	}
	now := s.clock.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, agent := range s.agents {
		if agent.revoked {
			continue
		}
		if bearer == agent.current.value && now.Before(agent.current.expiresAt) {
			agent.previous = nil
			return agent
		}
		if agent.previous != nil && bearer == agent.previous.value && now.Before(agent.previous.expiresAt) {
			return agent
		}
	}
	return nil
}

// issue makes a credential, which the platform would show once and keep only the hash of.
func (s *Stub) issue() (issued, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return issued{}, err
	}
	return issued{value: "agk_" + base64.RawURLEncoding.EncodeToString(random), expiresAt: s.clock.Now().Add(s.credentialLife)}, nil
}

func (s *Stub) register(payload map[string]any) (int, any) {
	token, _ := payload["token"].(string)
	s.mu.Lock()
	known := s.tokens[token]
	s.mu.Unlock()
	if !known {
		return 401, map[string]string{"error": "the registration token is not valid: it is unknown, used or expired"}
	}
	id := fmt.Sprintf("00000000-0000-4000-8000-%012d", len(s.AgentIDs())+1)
	credential, err := s.issue()
	if err != nil {
		return 500, map[string]string{"error": err.Error()}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, token)
	s.agents[id] = &agentRecord{
		id: id, current: credential, hostName: payload["hostName"].(string), version: payload["version"].(string), lastSeen: s.clock.Now(),
		os: payload["os"].(string), arch: payload["arch"].(string),
	}
	return 201, map[string]any{"agentId": id, "credential": credential.value, "expiresAt": credential.expiresAt.UTC().Format(time.RFC3339), "pollAfterSeconds": s.pollSeconds}
}

// rotate makes the Agent's new credential. The one presented is kept as the previous, accepted until the new one is first
// used; so an Agent that never got the answer, and asks again with the same credential, gets another new one.
func (s *Stub) rotate(agent *agentRecord, presented string) (int, any) {
	next, err := s.issue()
	if err != nil {
		return 500, map[string]string{"error": err.Error()}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if presented == agent.current.value {
		replaced := agent.current
		agent.previous = &replaced
	}
	agent.current = next
	return 200, map[string]any{"credential": next.value, "expiresAt": next.expiresAt.UTC().Format(time.RFC3339)}
}

// dropConnection ends the call without an answer.
func (s *Stub) dropConnection(w http.ResponseWriter) {
	conn, _, err := w.(http.Hijacker).Hijack()
	if err == nil {
		conn.Close()
	}
}

// reply validates the answer against the contract before sending it: the stub holds itself to the contract too.
func (s *Stub) reply(w http.ResponseWriter, r *http.Request, status int, answer any, op *operation) {
	encoded, _ := json.Marshal(answer)
	if op != nil {
		if schema := op.responses[status]; schema != nil {
			value, _ := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
			if err := schema.Validate(value); err != nil {
				s.violation("%s %s: the stub's %d answer does not conform to the contract: %v", r.Method, r.URL.Path, status, err)
			}
		} else {
			s.violation("%s %s: the contract has no %d answer", r.Method, r.URL.Path, status)
		}
	}
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(encoded)
}
