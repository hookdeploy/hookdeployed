package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestClearEnrollmentRemovesAllFourAndLoadFails(t *testing.T) {
	dir := t.TempDir()
	for _, name := range EnrollmentFiles {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := ClearEnrollment(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("Load must fail after ClearEnrollment")
	}
	for _, name := range EnrollmentFiles {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s still present: %v", name, err)
		}
	}
}

func TestClearEnrollmentClientCrtFirstMakesPartialUnenrolled(t *testing.T) {
	if EnrollmentFiles[0] != "client.key" {
		t.Fatalf("first delete must be client.key so a partial wipe cannot leave a usable identity, got %q", EnrollmentFiles[0])
	}
}
