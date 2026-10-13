package credential_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"certificate-platform/agent/internal/credential"
)

var issued = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func record() credential.Record {
	return credential.Record{
		PlatformURL: "https://certs.example.com", AgentID: "a-1", Credential: "agk_very-secret",
		IssuedAt: issued, ExpiresAt: issued.Add(30 * 24 * time.Hour),
	}
}

func TestARecordIsStoredAndReadBackAndReplacedAsAWhole(t *testing.T) {
	store := credential.Store{Dir: filepath.Join(t.TempDir(), "state")}
	if _, err := store.Load(); !errors.Is(err, credential.ErrNotRegistered) {
		t.Fatalf("got %v", err)
	}
	if err := store.Save(record()); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load()
	if err != nil || got != record() {
		t.Fatalf("read back %v, %v", got, err)
	}
	next := record()
	next.Credential = "agk_next"
	if err := store.Save(next); err != nil {
		t.Fatal(err)
	}
	if got, _ := store.Load(); got.Credential != "agk_next" {
		t.Fatalf("read back %v", got)
	}
	// Nothing is left beside it from the atomic write.
	entries, _ := os.ReadDir(store.Dir)
	if len(entries) != 1 || entries[0].Name() != "credential.json" {
		t.Fatalf("the directory holds %v", entries)
	}
	if err := store.Save(credential.Record{PlatformURL: "x"}); err == nil {
		t.Fatal("stored a registration without a credential")
	}
}

func TestTheStoreIsForTheServiceAccountAloneAndAMalformedFileIsRefusedWithoutQuotingIt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes do not protect files on Windows; the installer sets the directory's ACL")
	}
	store := credential.Store{Dir: filepath.Join(t.TempDir(), "state")}
	if err := store.Save(record()); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{store.Dir: 0o700, filepath.Join(store.Dir, "credential.json"): 0o600} {
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != want {
			t.Fatalf("%s: %v, %v", path, info, err)
		}
	}
	path := filepath.Join(store.Dir, "credential.json")
	if err := os.WriteFile(path, []byte(`{"credential": "agk_very-secret" oops`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := store.Load()
	if err == nil || strings.Contains(err.Error(), "agk_") {
		t.Fatalf("got %v", err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil || strings.Contains(err.Error(), "agk_") {
		t.Fatalf("a store readable by its group was loaded: %v", err)
	}
}

func TestAFormattedRecordDoesNotShowTheCredential(t *testing.T) {
	r := record()
	for _, text := range []string{fmt.Sprint(r), fmt.Sprintf("%v", &r), fmt.Sprintf("%+v", r), fmt.Sprintf("%#v", r)} {
		if strings.Contains(text, "agk_") {
			t.Fatalf("formatted as %s", text)
		}
	}
}

func TestRotationIsDueWithAThirdOfTheLifeLeft(t *testing.T) {
	if got, want := record().RotationDue(), issued.Add(20*24*time.Hour); !got.Equal(want) {
		t.Fatalf("due %v, want %v", got, want)
	}
}
