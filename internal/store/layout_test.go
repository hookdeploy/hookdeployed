package store

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hookdeploy/hookdeployed/internal/mtls"
)

func writeFlat(t *testing.T, root string) {
	t.Helper()
	pki, err := mtls.GenerateTestPKI()
	if err != nil {
		t.Fatal(err)
	}
	if err := Write(root, encodeDERCert(pki.CACert.Raw), encodeDERCert(pki.ClientCert.Raw), encodeECKey(pki.ClientKey)); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateFlatStoreSetsActiveAndLooksEnrolled(t *testing.T) {
	root := t.TempDir()
	writeFlat(t, root)
	legacy := filepath.Join(filepath.Dir(root), SystemInfoFile)
	if err := os.WriteFile(legacy, []byte(`{"agent_id":"old"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := EnsureLayout(root); err != nil {
		t.Fatal(err)
	}
	if IsFlatStore(root) {
		t.Fatal("root still looks flat")
	}
	if HasMigrating(root) {
		t.Fatal(".migrating should be gone")
	}
	active, err := ReadActive(root)
	if err != nil {
		t.Fatal(err)
	}
	if active != mtls.TestClientOU {
		t.Fatalf("active=%q want %q", active, mtls.TestClientOU)
	}
	if !LooksEnrolled(root) {
		t.Fatal("migrated store should look enrolled")
	}
	dir := OrgDir(root, active)
	if _, err := Load(dir); err != nil {
		t.Fatalf("load org dir: %v", err)
	}
	meta, err := LoadOrgMeta(dir)
	if err != nil {
		t.Fatal(err)
	}
	if meta.ID != mtls.TestClientOU {
		t.Fatalf("org.json id=%q", meta.ID)
	}
	if meta.Name != "" || meta.Slug != "" {
		t.Fatalf("migrated org.json should have id only, got %#v", meta)
	}
	if _, err := os.Stat(filepath.Join(dir, SystemInfoFile)); err != nil {
		t.Fatalf("legacy system-info should move into org dir: %v", err)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatal("legacy sibling system-info.json still present")
	}
	info, err := os.Stat(ActivePath(root))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o400 == 0 {
		t.Fatalf("active missing read bit: %o", info.Mode().Perm())
	}
}

func TestInterruptedMigrationDoesNotLookEnrolled(t *testing.T) {
	root := t.TempDir()
	writeFlat(t, root)
	dest := OrgDir(root, mtls.TestClientOU)
	if err := os.MkdirAll(dest, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(root, "client.key"), filepath.Join(dest, "client.key")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(migratingPath(root), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if LooksEnrolled(root) {
		t.Fatal("half-migrated store must not look enrolled")
	}
	if _, err := Load(root); err == nil {
		t.Fatal("root Load must fail without client.key")
	}
	if _, err := Load(dest); err == nil {
		t.Fatal("partial dest must not Load")
	}

	if err := EnsureLayout(root); err != nil {
		t.Fatal(err)
	}
	if !LooksEnrolled(root) {
		t.Fatal("retry should finish migration")
	}
}

func TestStaleActiveIsNotFatal(t *testing.T) {
	root := t.TempDir()
	if err := WriteActive(root, "missing-org"); err != nil {
		t.Fatal(err)
	}
	dir, err := ResolveActiveDir(root)
	if dir != "" || err != ErrNotEnrolled {
		t.Fatalf("stale active: dir=%q err=%v", dir, err)
	}
	active, err := ReadActive(root)
	if err != nil {
		t.Fatal(err)
	}
	if active != "" {
		t.Fatalf("stale active should be cleared, got %q", active)
	}
}

func TestResolveActiveDirNoActiveWithOrgs(t *testing.T) {
	root := t.TempDir()
	pki, err := mtls.GenerateTestPKI()
	if err != nil {
		t.Fatal(err)
	}
	a := OrgDir(root, "org-a")
	if err := Write(a, encodeDERCert(pki.CACert.Raw), encodeDERCert(pki.ClientCert.Raw), encodeECKey(pki.ClientKey)); err != nil {
		t.Fatal(err)
	}
	if err := WriteOrgMeta(a, OrgMeta{ID: "org-a", Name: "Alpha", Slug: "alpha"}); err != nil {
		t.Fatal(err)
	}

	dir, err := ResolveActiveDir(root)
	if dir != "" || err != ErrNoActive {
		t.Fatalf("dir=%q err=%v want ErrNoActive", dir, err)
	}
	got := ExplainResolve(root, err)
	if got == nil || !strings.Contains(got.Error(), "agent switch") || !strings.Contains(got.Error(), "org-a") {
		t.Fatalf("explain=%v", got)
	}
	if strings.Contains(got.Error(), "agent enroll") {
		t.Fatalf("must not send them to enroll: %v", got)
	}
}

func TestRemoveOrgLeavesOthersAndClearsActive(t *testing.T) {
	root := t.TempDir()
	pki, err := mtls.GenerateTestPKI()
	if err != nil {
		t.Fatal(err)
	}
	a := OrgDir(root, "org-a")
	b := OrgDir(root, "org-b")
	if err := Write(a, encodeDERCert(pki.CACert.Raw), encodeDERCert(pki.ClientCert.Raw), encodeECKey(pki.ClientKey)); err != nil {
		t.Fatal(err)
	}
	if err := Write(b, encodeDERCert(pki.CACert.Raw), encodeDERCert(pki.ClientCert.Raw), encodeECKey(pki.ClientKey)); err != nil {
		t.Fatal(err)
	}
	if err := WriteOrgMeta(a, OrgMeta{ID: "org-a", Name: "A", Slug: "a"}); err != nil {
		t.Fatal(err)
	}
	if err := WriteOrgMeta(b, OrgMeta{ID: "org-b", Name: "B", Slug: "b"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a, SystemInfoFile), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteActive(root, "org-a"); err != nil {
		t.Fatal(err)
	}

	if err := RemoveOrg(root, "org-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(a); !os.IsNotExist(err) {
		t.Fatal("revoked org dir should be gone")
	}
	if _, err := Load(b); err != nil {
		t.Fatalf("other org must survive: %v", err)
	}
	active, err := ReadActive(root)
	if err != nil {
		t.Fatal(err)
	}
	if active != "" {
		t.Fatalf("active should be cleared, not switched, got %q", active)
	}
}

func TestMatchAndAmbiguity(t *testing.T) {
	orgs := []Enrollment{
		{ID: "id-1", Name: "Acme", Slug: "acme"},
		{ID: "id-2", Name: "Acme", Slug: "acme-eu"},
		{ID: "id-3", Name: "Beta", Slug: "beta"},
	}
	got, err := Match(orgs, "beta")
	if err != nil || got.ID != "id-3" {
		t.Fatalf("slug match: %#v err=%v", got, err)
	}
	got, err = Match(orgs, "ID-3")
	if err != nil || got.ID != "id-3" {
		t.Fatalf("id fold: %#v err=%v", got, err)
	}
	if _, err := Match(orgs, "Acme"); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("name clash should be ambiguous: %v", err)
	}
	if _, err := Match(orgs, "nope"); err == nil {
		t.Fatal("unknown should error")
	}
}

func TestFormatListMarksActive(t *testing.T) {
	text := FormatList([]Enrollment{
		{ID: "id-1", Name: "Acme", Slug: "acme", Active: false},
		{ID: "id-2", Name: "", Slug: "", Active: true},
	})
	if !strings.Contains(text, "* id-2") {
		t.Fatalf("active mark:\n%s", text)
	}
	if !strings.Contains(text, "  id-1  Acme  acme") {
		t.Fatalf("inactive row:\n%s", text)
	}
	if !strings.Contains(text, "—") {
		t.Fatalf("empty name/slug should be em dash:\n%s", text)
	}
}

const formatListGolden = "  id-1  Acme  acme\n* id-2  —  —\n"

func TestFormatListTextUnchanged(t *testing.T) {
	got := FormatList([]Enrollment{
		{ID: "id-1", Name: "Acme", Slug: "acme", Active: false, AgentID: "ignored-in-text"},
		{ID: "id-2", Name: "", Slug: "", Active: true, AgentID: "also-ignored"},
	})
	if got != formatListGolden {
		t.Fatalf("human-readable list changed:\n got %q\nwant %q", got, formatListGolden)
	}
}

func TestPrintListDefaultMatchesFormatList(t *testing.T) {
	orgs := []Enrollment{
		{ID: "id-1", Name: "Acme", Slug: "acme", Active: false},
		{ID: "id-2", Name: "", Slug: "", Active: true},
	}
	var buf bytes.Buffer
	if err := PrintList(&buf, orgs, false); err != nil {
		t.Fatal(err)
	}
	if buf.String() != FormatList(orgs) || buf.String() != formatListGolden {
		t.Fatalf("default output drifted:\n%s", buf.String())
	}
}

func TestPrintListJSONRoundTrip(t *testing.T) {
	root := t.TempDir()
	seedTwoOrgs(t, root)
	orgs, err := List(root)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := PrintList(&buf, orgs, true); err != nil {
		t.Fatal(err)
	}
	var parsed []struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Slug    string `json:"slug"`
		Active  bool   `json:"active"`
		AgentID string `json:"agent_id"`
	}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, buf.String())
	}
	if len(parsed) != 2 {
		t.Fatalf("len=%d want 2: %s", len(parsed), buf.String())
	}
	byID := map[string]struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Slug    string `json:"slug"`
		Active  bool   `json:"active"`
		AgentID string `json:"agent_id"`
	}{}
	for _, row := range parsed {
		byID[row.ID] = row
	}
	alpha, ok := byID["org-a"]
	if !ok {
		t.Fatalf("missing org-a: %s", buf.String())
	}
	if alpha.Name != "Alpha" || alpha.Slug != "alpha" || !alpha.Active {
		t.Fatalf("org-a=%#v", alpha)
	}
	if alpha.AgentID != mtls.TestClientCN {
		t.Fatalf("agent_id=%q want %q", alpha.AgentID, mtls.TestClientCN)
	}
	beta := byID["org-b"]
	if beta.Name != "Beta" || beta.Active || beta.AgentID != mtls.TestClientCN {
		t.Fatalf("org-b=%#v", beta)
	}
	if strings.Contains(buf.String(), `"dir"`) {
		t.Fatalf("json must not leak Dir: %s", buf.String())
	}
}

func TestPrintListJSONEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := PrintList(&buf, nil, true); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(buf.String()) != "[]" {
		t.Fatalf("empty json=%q", buf.String())
	}
	var parsed []Enrollment
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if parsed == nil || len(parsed) != 0 {
		t.Fatalf("parsed=%#v", parsed)
	}
}

func TestPrintListEmptyTextStillErrors(t *testing.T) {
	var buf bytes.Buffer
	err := PrintList(&buf, nil, false)
	if err == nil || err.Error() != "no enrolled organizations — run `agent enroll`" {
		t.Fatalf("err=%v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("stdout should stay empty, got %q", buf.String())
	}
}

func encodeDERCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func encodeECKey(key *ecdsa.PrivateKey) []byte {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}
