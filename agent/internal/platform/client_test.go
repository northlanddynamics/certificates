package platform_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"certificate-platform/agent/internal/platform"
)

func TestOnlyHTTPSIsAcceptedExceptForALoopbackHost(t *testing.T) {
	for url, ok := range map[string]bool{
		"https://certs.example.com":     true,
		"https://192.0.2.10:8443":       true,
		"http://localhost:3000":         true,
		"http://127.0.0.1:3000":         true,
		"http://127.4.5.6":              true,
		"http://[::1]:3000":             true,
		"http://certs.example.com":      false,
		"http://192.0.2.10":             false,
		"http://[2001:db8::1]":          false,
		"http://localhost.example.com":  false,
		"http://127.0.0.1.example.com":  false,
		"http://user:pw@localhost:3000": false,
		"ftp://localhost":               false,
		"localhost:3000":                false,
		"":                              false,
	} {
		_, err := platform.NewClient(url, platform.Options{})
		if (err == nil) != ok {
			t.Errorf("%q: accepted=%v (%v), want %v", url, err == nil, err, ok)
		}
	}
}

func TestTheCredentialGoesInTheAuthorizationHeaderAndInNoErrorOrRedirect(t *testing.T) {
	var seen []string
	var other bool
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { other = true }))
	defer elsewhere.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("authorization"))
		if r.URL.Path == "/api/agent/credential" {
			http.Redirect(w, r, elsewhere.URL, http.StatusTemporaryRedirect)
			return
		}
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"no"}`))
	}))
	defer server.Close()
	client, err := platform.NewClient(server.URL, platform.Options{Credential: func() string { return "agk_secret" }})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Poll(context.Background(), "1")
	if !platform.Rejected(err) || strings.Contains(err.Error(), "agk_") {
		t.Fatalf("got %v", err)
	}
	if _, err = client.RotateCredential(context.Background()); err == nil || strings.Contains(err.Error(), "agk_") {
		t.Fatalf("got %v", err)
	}
	if len(seen) != 2 || seen[0] != "Bearer agk_secret" || other {
		t.Fatalf("saw %v, followed a redirect: %v", seen, other)
	}

	// Registering presents no credential.
	seen = nil
	anonymous, _ := platform.NewClient(server.URL, platform.Options{})
	_, _ = anonymous.Register(context.Background(), platform.RegistrationRequest{Token: "t"})
	if len(seen) != 1 || seen[0] != "" {
		t.Fatalf("saw %v", seen)
	}
}
