package mtls

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestClientTLSConfigForSetsServerName(t *testing.T) {
	pki, err := GenerateTestPKI()
	if err != nil {
		t.Fatal(err)
	}
	material := &ClientMaterial{
		CACert:     pki.CACert,
		ClientCert: pki.ClientCert,
		ClientKey:  pki.ClientKey,
	}

	localhost := material.ClientTLSConfig()
	if localhost.ServerName != DefaultServerName {
		t.Fatalf("ClientTLSConfig ServerName=%q want %q", localhost.ServerName, DefaultServerName)
	}

	cfg, err := material.ClientTLSConfigFor("relay-test-1a.hookdeploy.dev")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerName != "relay-test-1a.hookdeploy.dev" {
		t.Fatalf("ServerName=%q", cfg.ServerName)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion=%#x want TLS1.3", cfg.MinVersion)
	}
	if len(cfg.Certificates) != 1 || len(cfg.Certificates[0].Certificate) < 1 {
		t.Fatal("expected leaf certificate")
	}
	if cfg.RootCAs == nil {
		t.Fatal("RootCAs missing")
	}

	if _, err := material.ClientTLSConfigFor(""); err == nil {
		t.Fatal("empty server name should fail")
	}
	if _, err := material.ClientTLSConfigFor("   "); err == nil {
		t.Fatal("whitespace server name should fail")
	}
}

func TestWriteAndLoadRenewalToken(t *testing.T) {
	pki, err := GenerateTestPKI()
	if err != nil {
		t.Fatal(err)
	}
	caPEM := encodeCert(pki.CACert.Raw)
	certPEM := encodeCert(pki.ClientCert.Raw)
	keyPEM := encodeKey(pki.ClientKey)
	token := []byte("hd_agentrenew_us_" + "ab" + "cd")

	dir := t.TempDir()
	if err := WriteClientDir(dir, caPEM, certPEM, keyPEM, token); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ca.crt", "client.crt", "client.key", "renewal.token"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode=%o want 0600", name, info.Mode().Perm())
		}
	}
	loaded, err := LoadClientDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.RenewalToken != string(token) {
		t.Fatalf("RenewalToken=%q", loaded.RenewalToken)
	}
}

func TestWriteClientDirNilTokenPreservesExistingFile(t *testing.T) {
	pki, err := GenerateTestPKI()
	if err != nil {
		t.Fatal(err)
	}
	caPEM := encodeCert(pki.CACert.Raw)
	certPEM := encodeCert(pki.ClientCert.Raw)
	keyPEM := encodeKey(pki.ClientKey)
	dir := t.TempDir()
	if err := WriteClientDir(dir, caPEM, certPEM, keyPEM, []byte("hd_agentrenew_us_keep")); err != nil {
		t.Fatal(err)
	}
	if err := WriteClientDir(dir, caPEM, certPEM, keyPEM, nil); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "renewal.token"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hd_agentrenew_us_keep" {
		t.Fatalf("token=%q want preserved", got)
	}
}

func TestWriteClientDirTokenSurvivesCertWriteFailure(t *testing.T) {
	pki, err := GenerateTestPKI()
	if err != nil {
		t.Fatal(err)
	}
	caPEM := encodeCert(pki.CACert.Raw)
	certPEM := encodeCert(pki.ClientCert.Raw)
	keyPEM := encodeKey(pki.ClientKey)
	dir := t.TempDir()
	if err := WriteClientDir(dir, caPEM, certPEM, keyPEM, []byte("hd_agentrenew_us_old")); err != nil {
		t.Fatal(err)
	}
	oldCert, err := os.ReadFile(filepath.Join(dir, "client.crt"))
	if err != nil {
		t.Fatal(err)
	}

	caPath := filepath.Join(dir, "ca.crt")
	if err := os.Remove(caPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(caPath, 0o700); err != nil {
		t.Fatal(err)
	}

	newToken := []byte("hd_agentrenew_us_new")
	err = WriteClientDir(dir, []byte("new-ca"), []byte("new-cert"), keyPEM, newToken)
	if err == nil {
		t.Fatal("expected write of ca.crt to fail because it is a directory")
	}
	got, err := os.ReadFile(filepath.Join(dir, "renewal.token"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(newToken) {
		t.Fatalf("token=%q want new (written before certs)", got)
	}
	still, err := os.ReadFile(filepath.Join(dir, "client.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(still) != string(oldCert) {
		t.Fatal("client.crt should still be the old cert after ca.crt write failed")
	}
}

func TestLoadClientDirWithoutRenewalToken(t *testing.T) {
	pki, err := GenerateTestPKI()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := WriteClientDir(dir, encodeCert(pki.CACert.Raw), encodeCert(pki.ClientCert.Raw), encodeKey(pki.ClientKey), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "renewal.token")); !os.IsNotExist(err) {
		t.Fatalf("renewal.token should be absent, err=%v", err)
	}
	loaded, err := LoadClientDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.RenewalToken != "" {
		t.Fatalf("RenewalToken=%q want empty", loaded.RenewalToken)
	}
}
