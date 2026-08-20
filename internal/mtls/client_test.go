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
