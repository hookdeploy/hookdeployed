package store

import (
	"bytes"
	"strings"
	"testing"

	"github.com/hookdeploy/hookdeployed/internal/mtls"
)

func seedTwoOrgs(t *testing.T, root string) {
	t.Helper()
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
	if err := WriteOrgMeta(a, OrgMeta{ID: "org-a", Name: "Alpha", Slug: "alpha"}); err != nil {
		t.Fatal(err)
	}
	if err := WriteOrgMeta(b, OrgMeta{ID: "org-b", Name: "Beta", Slug: "beta"}); err != nil {
		t.Fatal(err)
	}
	if err := WriteActive(root, "org-a"); err != nil {
		t.Fatal(err)
	}
}

func TestRunSwitchDirectAndList(t *testing.T) {
	root := t.TempDir()
	seedTwoOrgs(t, root)

	var out bytes.Buffer
	if err := RunSwitch(root, []string{"beta"}, nil, &out, false); err != nil {
		t.Fatal(err)
	}
	active, err := ReadActive(root)
	if err != nil || active != "org-b" {
		t.Fatalf("active=%q err=%v", active, err)
	}
	if !strings.Contains(out.String(), "Beta") {
		t.Fatalf("switch output: %q", out.String())
	}

	orgs, err := List(root)
	if err != nil {
		t.Fatal(err)
	}
	text := FormatList(orgs)
	if !strings.Contains(text, "* org-b") {
		t.Fatalf("list after switch:\n%s", text)
	}
}

func TestRunSwitchNoArgNonTTYPrintsListAndErrors(t *testing.T) {
	root := t.TempDir()
	seedTwoOrgs(t, root)

	var out bytes.Buffer
	err := RunSwitch(root, nil, strings.NewReader("this would hang\n"), &out, false)
	if err == nil || !strings.Contains(err.Error(), SwitchNeedsTTY) {
		t.Fatalf("err=%v", err)
	}
	if !strings.Contains(out.String(), "org-a") || !strings.Contains(out.String(), "org-b") {
		t.Fatalf("list not printed:\n%s", out.String())
	}
	active, _ := ReadActive(root)
	if active != "org-a" {
		t.Fatalf("non-TTY switch must not change active, got %q", active)
	}
}

func TestRunSwitchInteractivePicker(t *testing.T) {
	root := t.TempDir()
	seedTwoOrgs(t, root)

	var out bytes.Buffer
	if err := RunSwitch(root, nil, strings.NewReader("2\n"), &out, true); err != nil {
		t.Fatal(err)
	}
	active, err := ReadActive(root)
	if err != nil || active != "org-b" {
		t.Fatalf("active=%q err=%v", active, err)
	}
}

func TestRunSwitchAmbiguous(t *testing.T) {
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
	if err := WriteOrgMeta(a, OrgMeta{ID: "org-a", Name: "Acme", Slug: "acme"}); err != nil {
		t.Fatal(err)
	}
	if err := WriteOrgMeta(b, OrgMeta{ID: "org-b", Name: "Acme", Slug: "acme-eu"}); err != nil {
		t.Fatal(err)
	}
	if err := WriteActive(root, "org-a"); err != nil {
		t.Fatal(err)
	}
	err = RunSwitch(root, []string{"Acme"}, nil, ioDiscard{}, false)
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("err=%v", err)
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }
