package dnsrelay

import (
	"context"
	"encoding/json"
	"strings"
	"time"
)

// The work item types by which the platform relays DNS Provider operations to an Agent.
const (
	WorkPresent = "dns.present"
	WorkCleanUp = "dns.cleanup"
	WorkTest    = "dns.test"
)

// Handles reports whether the work item type is a DNS Provider operation.
func Handles(workType string) bool {
	return workType == WorkPresent || workType == WorkCleanUp || workType == WorkTest
}

// operationTimeout bounds one operation, whatever the DNS service does. It is shorter than the time the platform gives an
// Agent before it asks another, so that an Agent does not go on with what the platform has given up on. (A connection
// test is two operations of up to ten seconds.)
const operationTimeout = 30 * time.Second

// payload is what a DNS Provider work item carries: the provider as plain data, and for a record operation the record.
type payload struct {
	Provider struct {
		Type     string          `json:"type"`
		Settings json.RawMessage `json:"settings"`
		Secret   string          `json:"secret"`
	} `json:"provider"`
	Record *Record `json:"record"`
}

// Carry out the operation a work item of a DNS type asks for. It returns nil when it worked, and otherwise an *Error saying
// how it did not; the message is safe to report, and holds nothing of the provider's secret.
func Carry(ctx context.Context, workType string, raw map[string]json.RawMessage) (failure *Error) {
	var work payload
	encoded, err := json.Marshal(raw)
	if err != nil || json.Unmarshal(encoded, &work) != nil || work.Provider.Type == "" || len(work.Provider.Settings) == 0 || work.Provider.Secret == "" {
		return rejected("the work item does not describe a DNS Provider operation")
	}
	secret := work.Provider.Secret
	defer func() {
		// Whatever went wrong is reported without the credentials, however a message came to mention them.
		if recovered := recover(); recovered != nil {
			failure = rejected("the Agent could not carry the operation out")
		}
		if failure != nil {
			failure = &Error{Kind: failure.Kind, Message: redact(failure.Message, secret)}
		}
	}()

	provider, err := New(work.Provider.Type, work.Provider.Settings, secret)
	if err != nil {
		return asError(err)
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	switch workType {
	case WorkPresent, WorkCleanUp:
		if work.Record == nil || work.Record.Name == "" {
			return rejected("the work item has no record")
		}
		if workType == WorkPresent {
			err = provider.Present(ctx, *work.Record)
		} else {
			err = provider.CleanUp(ctx, *work.Record)
		}
	case WorkTest:
		err = provider.Test(ctx)
	default:
		return rejected("not a DNS Provider operation: %s", workType)
	}
	return asError(err)
}

func asError(err error) *Error {
	switch e := err.(type) {
	case nil:
		return nil
	case *Error:
		return e
	default:
		return unreachable("the operation failed: %v", err)
	}
}

// redact removes the secret, and the parts a credential pair is made of, from a message.
func redact(message, secret string) string {
	parts := []string{secret}
	if _, password, ok := strings.Cut(secret, ":"); ok {
		parts = append(parts, password)
	}
	for _, part := range parts {
		if len(part) >= 4 {
			message = strings.ReplaceAll(message, part, "[secret]")
		}
	}
	return message
}
