package sysinfo

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hookdeploy/hookdeployed/internal/enroll"
	"github.com/hookdeploy/hookdeployed/internal/mtls"
)

const testToken = "hd_agentrenew_us_" + "ab0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"

func writeEnrolledWithToken(t *testing.T, dir, token string) {
	t.Helper()
	pki, err := mtls.GenerateTestPKI()
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pki.CACert.Raw})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pki.ClientCert.Raw})
	keyPEM, err := enroll.EncodeKey(pki.ClientKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := mtls.WriteClientDir(dir, caPEM, certPEM, keyPEM, []byte(token)); err != nil {
		t.Fatal(err)
	}
}

func TestMaybeReportSendsOnceThenSuppresses(t *testing.T) {
	certs := filepath.Join(t.TempDir(), "certs")
	writeEnrolledWithToken(t, certs, testToken)

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/v1/agents/system-info" {
			t.Errorf("path=%s", r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		var body map[string]string
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("json: %v", err)
		}
		if body["renewal_token"] != testToken {
			t.Errorf("token missing from body")
		}
		if body["os"] == "" || body["arch"] == "" {
			t.Errorf("os/arch empty: %v", body)
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	fixed := Info{Hostname: "box", OS: "linux", OSVersion: "Ubuntu 24.04.1 LTS", Arch: "amd64", AgentVersion: "dev"}
	now := time.Unix(1_700_000_000, 0)
	collect := func() Info { return fixed }

	if err := maybeReport(srv.URL, certs, collect, func() time.Time { return now }); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 1 {
		t.Fatalf("hits=%d want 1", hits.Load())
	}
	if err := maybeReport(srv.URL, certs, collect, func() time.Time { return now.Add(time.Hour) }); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 1 {
		t.Fatalf("repeat should be suppressed; hits=%d", hits.Load())
	}

	changed := fixed
	changed.Hostname = "other"
	if err := maybeReport(srv.URL, certs, func() Info { return changed }, func() time.Time { return now.Add(RetryInterval) }); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 2 {
		t.Fatalf("changed value should send; hits=%d", hits.Load())
	}
}

func TestMaybeReportFailureDoesNotRecordSentAndOmitsTokenFromLogs(t *testing.T) {
	certs := filepath.Join(t.TempDir(), "certs")
	writeEnrolledWithToken(t, certs, testToken)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", 500)
	}))
	defer srv.Close()

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(io.Discard)

	err := maybeReport(srv.URL, certs, Collect, time.Now)
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), testToken) {
		t.Fatalf("error leaked token: %v", err)
	}
	if strings.Contains(buf.String(), testToken) {
		t.Fatalf("logs leaked token: %s", buf.String())
	}

	prev, err := loadSnapshot(StatePath(certs))
	if err != nil {
		t.Fatal(err)
	}
	if prev.Sent != nil {
		t.Fatal("failed report must not record sent values")
	}
}

func TestMaybeReportSkipsWithoutToken(t *testing.T) {
	certs := filepath.Join(t.TempDir(), "certs")
	writeEnrolledWithToken(t, certs, "")
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()
	if err := maybeReport(srv.URL, certs, Collect, time.Now); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 0 {
		t.Fatal("must not POST without a renewal token")
	}
}

func TestPostReportErrorHasNoToken(t *testing.T) {
	err := postReport("http://127.0.0.1:1", testToken, Info{OS: "linux", Arch: "amd64"})
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), testToken) {
		t.Fatalf("error leaked token: %v", err)
	}
}
