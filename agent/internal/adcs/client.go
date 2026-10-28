// Package adcs is how the Agent reaches an Active Directory Certificate Services CA: as its own account (a gMSA on a
// domain-joined Windows host), never with a credential the platform gives it. The platform holds no AD credential and no
// ADCS key (ADR 0013). Client is the seam: the real one speaks MS-WCCE and is built only for Windows; a fake stands in for
// it in tests, and both keep the contract in adcstest.
package adcs

import (
	"context"
	"errors"
	"fmt"
)

// Kinds of failure, as the platform names them: ADCS answered and refused, or it could not be reached (another Agent may
// reach it from where it is).
const (
	Rejected    = "rejected"
	Unreachable = "unreachable"
)

// Error is how an operation failed. Message is for a person to read and holds nothing secret.
type Error struct {
	Kind    string
	Message string
}

func (e *Error) Error() string { return e.Message }

// Refused is an Error of the Rejected kind.
func Refused(format string, args ...any) *Error {
	return &Error{Kind: Rejected, Message: fmt.Sprintf(format, args...)}
}

// NotReached is an Error of the Unreachable kind.
func NotReached(format string, args ...any) *Error {
	return &Error{Kind: Unreachable, Message: fmt.Sprintf(format, args...)}
}

// AsError is err as an *Error: one that is not says nothing of whether ADCS answered, so it counts as not reached.
func AsError(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return NotReached("ADCS could not be reached: %v", err)
}

// Key algorithms a template may allow, as the platform names them.
var KeyAlgorithms = []string{"rsa", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521"}

// Template is a Certificate Template and its facts.
type Template struct {
	// Name is its ADCS (common) name, by which a request names it.
	Name        string
	OID         string
	DisplayName string
	// ExtendedKeyUsages are its EKUs, as OIDs.
	ExtendedKeyUsages []string
	// ValidityDays is how long what it issues is valid for.
	ValidityDays int
	// MinimumKeySize is in bits.
	MinimumKeySize int
	KeyAlgorithms  []string
	// ManagerApproval is whether a request under it waits for a CA manager.
	ManagerApproval bool
	// SubjectFromRequest is "Supply in the request", rather than building the subject from Active Directory.
	SubjectFromRequest bool
	// Enrollable is whether the Agent's account may enroll on it.
	Enrollable bool
	// Published is whether the CA publishes it.
	Published bool
}

// Client reaches the ADCS CA a config string (`host\CA Name`) names. Every error is an *Error.
type Client interface {
	// Chain is the CA's certificate, then each certificate above it up to its root, DER.
	Chain(ctx context.Context, configString string) ([][]byte, error)
	// Discover lists the Certificate Templates the CA publishes, with their facts.
	Discover(ctx context.Context, configString string) ([]Template, error)
}
