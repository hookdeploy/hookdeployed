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

func TestWriteOrgMetaIsNotSecretAndLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := WriteOrgMeta(dir, OrgMeta{ID: "org-1", Name: "Acme Corp", Slug: "acme"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, OrgMetaFile))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o400 == 0 {
		t.Fatalf("org.json missing: mode=%o", info.Mode().Perm())
	}
	meta, err := LoadOrgMeta(dir)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Name != "Acme Corp" || meta.ID != "org-1" || meta.Slug != "acme" {
		t.Fatalf("meta=%#v", meta)
	}
	if err := ClearEnrollment(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrgMeta(dir); !os.IsNotExist(err) {
		t.Fatalf("org.json should be removed on ClearEnrollment, err=%v", err)
	}
}
