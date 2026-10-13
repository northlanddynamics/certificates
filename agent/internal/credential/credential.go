// Package credential is what the Agent keeps to prove who it is (ADR 0006): the credential the platform made for it at Agent
// Registration or at its latest rotation, with when it was received and when it ends, and where the Agent registered. It
// lives in a file in the state directory that only the service account may read. A credential is a secret: nothing here, and
// nothing that uses it, may log it or put it in an error.
package credential

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// ErrNotRegistered is returned by Load when the store holds no credential: the Agent has not registered.
var ErrNotRegistered = errors.New("this Agent is not registered: run `agent register` first")

// Record is what the Agent remembers about its registration.
type Record struct {
	PlatformURL string `json:"platformUrl"`
	AgentID     string `json:"agentId"`
	// Credential is the bearer credential (`agk_...`), a secret.
	Credential string `json:"credential"`
	// IssuedAt is when the Agent received the credential, and ExpiresAt when the platform says it ends: the credential's life
	// is the time between them.
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// String and GoString keep the credential out of anything that formats a Record, a log line included.
func (r Record) String() string {
	return fmt.Sprintf("{agent %s at %s, credential until %s}", r.AgentID, r.PlatformURL, r.ExpiresAt.Format(time.RFC3339))
}

func (r Record) GoString() string { return r.String() }

// RotationDue is when the credential is rotated: with a third of its life left.
func (r Record) RotationDue() time.Time {
	return r.IssuedAt.Add(r.ExpiresAt.Sub(r.IssuedAt) * 2 / 3)
}

// Store keeps the Record in a directory, in one file that is replaced as a whole, so that a crash never leaves a half-written
// credential.
type Store struct{ Dir string }

const file = "credential.json"

// Save replaces the stored Record. The directory and the file are for the service account alone; on Windows, where modes
// protect nothing, the state directory's ACL must (the installer sets it).
func (s Store) Save(r Record) error {
	if r.Credential == "" {
		return errors.New("there is no credential to store")
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(s.Dir, 0o700); err != nil && runtime.GOOS != "windows" {
		return err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return writeAtomically(filepath.Join(s.Dir, file), data)
}

// Load reads the stored Record. It refuses a store that others on the host can read, as the credential in it is the Agent.
func (s Store) Load() (Record, error) {
	path := filepath.Join(s.Dir, file)
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return Record{}, ErrNotRegistered
	}
	if err != nil {
		return Record{}, err
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return Record{}, fmt.Errorf("%s is readable by others (mode %o): it holds the Agent's credential", path, info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Record{}, err
	}
	var r Record
	// The error of a malformed file is not passed on as it is: it may quote what the file holds.
	if err := json.Unmarshal(data, &r); err != nil || r.Credential == "" || r.PlatformURL == "" || r.AgentID == "" {
		return Record{}, fmt.Errorf("%s does not hold a registration: register the Agent again", path)
	}
	return r, nil
}

// writeAtomically writes a file only its owner can read and renames it into place.
func writeAtomically(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
