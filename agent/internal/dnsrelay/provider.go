// Package dnsrelay carries out the DNS Provider operations the platform relays through this Agent: publishing and removing
// the TXT records of Domain Control Validation, and testing a connection, in DNS the platform cannot reach. It is the
// Agent's own implementation of each kind of DNS Provider, behaving as the platform's does when it runs one directly
// (server/src/issuance/dcv/dns-provider.ts): the same settings, the same refusals, the same messages. A provider is plain data (its
// type, settings and secret) that arrives with each operation, so nothing here keeps a secret between operations.
package dnsrelay

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// Error is a DNS Provider operation that failed, and how: Rejected when the DNS service answered and said no, Unreachable
// when it did not answer. Its message is for a person and never contains the provider's secret.
type Error struct {
	Kind    string
	Message string
}

const (
	Rejected    = "rejected"
	Unreachable = "unreachable"
)

func (e *Error) Error() string { return e.Message }

func rejected(format string, args ...any) *Error {
	return &Error{Kind: Rejected, Message: fmt.Sprintf(format, args...)}
}

func unreachable(format string, args ...any) *Error {
	return &Error{Kind: Unreachable, Message: fmt.Sprintf(format, args...)}
}

// Record is a TXT record: its name is inside the provider's zone, with or without the trailing dot.
type Record struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// recordPublisher is a Provider's way of changing records, which a connection test is made of.
type recordPublisher interface {
	Present(ctx context.Context, record Record) error
	CleanUp(ctx context.Context, record Record) error
}

// Provider is a connection to a DNS service, as the platform's DNS Provider interface has it.
type Provider interface {
	// Present publishes the record, leaving any other TXT records at its name alone.
	Present(ctx context.Context, record Record) error
	// CleanUp removes that record only, and succeeds when it is already gone.
	CleanUp(ctx context.Context, record Record) error
	// Test succeeds when the provider can publish and remove records in its zone, shown by doing both with a throwaway record.
	Test(ctx context.Context) error
}

// New is the provider of the given type with its settings (as JSON, the platform's own) and secret.
func New(providerType string, settings json.RawMessage, secret string) (Provider, error) {
	switch providerType {
	case "rfc2136":
		return newRfc2136(settings, secret)
	case "infoblox":
		return newInfoblox(settings, secret)
	default:
		return nil, rejected("this Agent does not know DNS Providers of the type %q; update the Agent", providerType)
	}
}

// normalize is a name as the platform keeps it: lower case, no trailing dot.
func normalize(name string) string { return strings.TrimSuffix(strings.ToLower(name), ".") }

// nameInZone is the record's name as kept here, which must be the zone or inside it.
func nameInZone(zone string, record Record) (string, error) {
	name := normalize(record.Name)
	if name != zone && !strings.HasSuffix(name, "."+zone) {
		return "", rejected("%s is not inside the zone %s", name, zone)
	}
	return name, nil
}

// testByThrowawayRecord publishes a throwaway TXT record where a challenge for the zone's own name goes, which any policy
// that lets the provider do its job allows, and removes it again. If the removal fails the error names the record to delete.
func testByThrowawayRecord(ctx context.Context, zone string, p recordPublisher) error {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	record := Record{Name: "_acme-challenge." + zone, Value: "certificate-platform-connection-test-" + hex.EncodeToString(random)}
	if err := p.Present(ctx, record); err != nil {
		return err
	}
	if err := p.CleanUp(ctx, record); err != nil {
		if failure, ok := err.(*Error); ok {
			return &Error{Kind: failure.Kind, Message: fmt.Sprintf("the test record was published but not removed (%s); remove the TXT record %q at %s by hand", failure.Message, record.Value, record.Name)}
		}
		return err
	}
	return nil
}

// domainName is a lower-case domain name without a trailing dot, or false when it cannot be one.
func domainName(name string) (string, bool) {
	name = normalize(name)
	if name == "" || len(name) > 253 {
		return "", false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return "", false
			}
		}
	}
	return name, true
}
