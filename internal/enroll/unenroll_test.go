package enroll

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hookdeploy/hookdeployed/internal/mtls"
	"github.com/hookdeploy/hookdeployed/internal/store"
)

const testRenewToken = "hd_agentrenew_us_unenrollfixture"

func seedOrg(t *testing.T, root, id, name, slug, token string) {
	t.Helper()
	pki, err := mtls.GenerateTestPKI()
	if err != nil {
		t.Fatal(err)
	}
	dir := store.OrgDir(root, id)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pki.CACert.Raw})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pki.ClientCert.Raw})
	keyDER, err := x509.MarshalECPrivateKey(pki.ClientKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := store.Write(dir, caPEM, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	if token != "" {
		if err := os.WriteFile(filepath.Join(dir, "renewal.token"), []byte(token), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.WriteOrgMeta(dir, store.OrgMeta{ID: id, Name: name, Slug: slug}); err != nil {
		t.Fatal(err)
	}
}

func TestUnenrollActiveDefaultServerThenDelete(t *testing.T) {
	root := t.TempDir()
	seedOrg(t, root, "org-a", "Alpha", "alpha", testRenewToken)
	seedOrg(t, root, "org-b", "Beta", "beta", testRenewToken)
	if err := store.WriteActive(root, "org-a"); err != nil {
		t.Fatal(err)
	}

	var called int
	var out bytes.Buffer
	err := Unenroll(UnenrollConfig{
		Root:      root,
		EnrollURL: "http://example.invalid",
		Yes:       true,
		Revoke: func(enrollURL, token string) error {
			called++
			if token != testRenewToken {
				t.Fatalf("token=%q", token)
			}
			return nil
		},
	}, strings.NewReader(""), &out, false)
	if err != nil {
		t.Fatal(err)
	}
	if called != 1 {
		t.Fatalf("revoke calls=%d", called)
	}
	if _, err := os.Stat(store.OrgDir(root, "org-a")); !os.IsNotExist(err) {
		t.Fatal("active org should be gone")
	}
	if _, err := store.Load(store.OrgDir(root, "org-b")); err != nil {
		t.Fatalf("other org must survive: %v", err)
	}
	active, _ := store.ReadActive(root)
	if active != "" {
		t.Fatalf("active should be cleared, got %q", active)
	}
	if !strings.Contains(out.String(), "unenrolled Alpha") || !strings.Contains(out.String(), "agent switch") {
		t.Fatalf("output=%q", out.String())
	}
}

func TestUnenrollArgumentMatching(t *testing.T) {
	root := t.TempDir()
	seedOrg(t, root, "org-a", "Alpha", "alpha", testRenewToken)
	seedOrg(t, root, "org-b", "Beta", "beta", testRenewToken)
	if err := store.WriteActive(root, "org-a"); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	err := Unenroll(UnenrollConfig{
		Root:  root,
		Yes:   true,
		Query: "beta",
		Revoke: func(enrollURL, token string) error {
			return nil
		},
	}, nil, &out, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store.OrgDir(root, "org-b")); !os.IsNotExist(err) {
		t.Fatal("matched org should be gone")
	}
	if _, err := store.Load(store.OrgDir(root, "org-a")); err != nil {
		t.Fatal(err)
	}
	active, _ := store.ReadActive(root)
	if active != "org-a" {
		t.Fatalf("unenrolling a non-active org must not clear active, got %q", active)
	}
}

func TestUnenrollTTYConfirmationRequiredAndYesSkips(t *testing.T) {
	root := t.TempDir()
	seedOrg(t, root, "org-a", "Alpha", "alpha", testRenewToken)
	if err := store.WriteActive(root, "org-a"); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	err := Unenroll(UnenrollConfig{
		Root: root,
		Revoke: func(enrollURL, token string) error {
			t.Fatal("should not revoke before confirm")
			return nil
		},
	}, strings.NewReader("n\n"), &out, true)
	if err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("err=%v", err)
	}
	if !strings.Contains(out.String(), UnenrollConfirmPrefix) {
		t.Fatalf("prompt=%q", out.String())
	}
	if _, err := store.Load(store.OrgDir(root, "org-a")); err != nil {
		t.Fatal("declined confirm must keep files")
	}

	out.Reset()
	if err := Unenroll(UnenrollConfig{
		Root:   root,
		Yes:    true,
		Revoke: func(enrollURL, token string) error { return nil },
	}, strings.NewReader(""), &out, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store.OrgDir(root, "org-a")); !os.IsNotExist(err) {
		t.Fatal("yes should delete")
	}
}

func TestUnenrollNonTTYWithoutYesErrors(t *testing.T) {
	root := t.TempDir()
	seedOrg(t, root, "org-a", "Alpha", "alpha", testRenewToken)
	if err := store.WriteActive(root, "org-a"); err != nil {
		t.Fatal(err)
	}
	err := Unenroll(UnenrollConfig{
		Root: root,
		Revoke: func(enrollURL, token string) error {
			t.Fatal("must not revoke")
			return nil
		},
	}, strings.NewReader("yes\n"), ioDiscard{}, false)
	if err == nil || !strings.Contains(err.Error(), UnenrollNeedsYes) {
		t.Fatalf("err=%v", err)
	}
	if _, err := store.Load(store.OrgDir(root, "org-a")); err != nil {
		t.Fatal("must keep files")
	}
}

func TestUnenrollServerFailureKeepsLocal(t *testing.T) {
	root := t.TempDir()
	seedOrg(t, root, "org-a", "Alpha", "alpha", testRenewToken)
	if err := store.WriteActive(root, "org-a"); err != nil {
		t.Fatal(err)
	}
	err := Unenroll(UnenrollConfig{
		Root: root,
		Yes:  true,
		Revoke: func(enrollURL, token string) error {
			return fmtUnenroll("worker down")
		},
	}, nil, ioDiscard{}, false)
	if err == nil || !strings.Contains(err.Error(), "could not revoke") {
		t.Fatalf("err=%v", err)
	}
	if !strings.Contains(err.Error(), "--local-only") {
		t.Fatalf("should suggest --local-only: %v", err)
	}
	if _, err := store.Load(store.OrgDir(root, "org-a")); err != nil {
		t.Fatal("server failure must not delete locally")
	}
}

func TestUnenrollLocalOnlySkipsServer(t *testing.T) {
	root := t.TempDir()
	seedOrg(t, root, "org-a", "Alpha", "alpha", testRenewToken)
	if err := store.WriteActive(root, "org-a"); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := Unenroll(UnenrollConfig{
		Root:      root,
		LocalOnly: true,
		Yes:       true,
		Revoke: func(enrollURL, token string) error {
			t.Fatal("local-only must not call the server")
			return nil
		},
	}, nil, &out, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store.OrgDir(root, "org-a")); !os.IsNotExist(err) {
		t.Fatal("local-only should delete")
	}
	if !strings.Contains(out.String(), "--local-only") {
		t.Fatalf("output must say the record remains: %q", out.String())
	}
}

func TestUnenrollNoActiveUsesExplainResolve(t *testing.T) {
	root := t.TempDir()
	seedOrg(t, root, "org-a", "Alpha", "alpha", testRenewToken)
	err := Unenroll(UnenrollConfig{Root: root, Yes: true}, nil, ioDiscard{}, false)
	if err == nil || !strings.Contains(err.Error(), "agent switch") {
		t.Fatalf("err=%v", err)
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }

func fmtUnenroll(msg string) error { return unenrollErr(msg) }

type unenrollErr string

func (e unenrollErr) Error() string { return string(e) }
