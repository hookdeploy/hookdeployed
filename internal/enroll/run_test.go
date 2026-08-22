package enroll

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hookdeploy/hookdeployed/internal/store"
)

func TestShouldRenewHalfwayAndExpired(t *testing.T) {
	now := time.Now()
	healthy := &struct {
		notBefore time.Time
		notAfter  time.Time
	}{now.Add(-time.Hour), now.Add(23 * time.Hour)}

	chain, err := GenerateStepLikeChainWindow("cn", "ou", healthy.notBefore, healthy.notAfter)
	if err != nil {
		t.Fatal(err)
	}
	if ShouldRenew(chain.Leaf, now) {
		t.Fatal("healthy leaf before halfway should not renew")
	}

	pastHalfway, err := GenerateStepLikeChainWindow("cn", "ou", now.Add(-20*time.Hour), now.Add(4*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !ShouldRenew(pastHalfway.Leaf, now) {
		t.Fatal("past halfway should renew")
	}

	expired, err := GenerateStepLikeChainWindow("cn", "ou", now.Add(-40*24*time.Hour), now.Add(-20*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !ShouldRenew(expired.Leaf, now) {
		t.Fatal("expired leaf should renew (vacation case)")
	}
}

type renewHit struct {
	path string
	body map[string]string
}

func startRenewServer(t *testing.T, chain *StepLikeChain, newToken string, hit *renewHit) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
			w.WriteHeader(500)
			return
		}
		var body map[string]string
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("json: %v", err)
			w.WriteHeader(400)
			return
		}
		hit.path = r.URL.Path
		hit.body = body
		_ = json.NewEncoder(w).Encode(map[string]string{
			"certificate":   string(chain.LeafPEM),
			"ca":            string(chain.IntermediatePEM),
			"certChain":     string(chain.CertChainPEM),
			"root":          string(chain.RootPEM),
			"agent_id":      chain.Leaf.Subject.CommonName,
			"org_id":        chain.Leaf.Subject.OrganizationalUnit[0],
			"renewal_token": newToken,
		})
	}))
}

func writeChain(t *testing.T, dir string, chain *StepLikeChain, token string) {
	t.Helper()
	keyPEM, err := EncodeKey(chain.LeafKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteBundle(dir, chain.RootPEM, chain.CertChainPEM, chain.LeafPEM, chain.IntermediatePEM, keyPEM, []byte(token)); err != nil {
		t.Fatal(err)
	}
}

func TestMaybeRenewTokenBody(t *testing.T) {
	now := time.Now()
	oldChain, err := GenerateStepLikeChainWindow("agent-1", "org-1", now.Add(-20*time.Hour), now.Add(4*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	newChain, err := GenerateStepLikeChain("agent-1", "org-1")
	if err != nil {
		t.Fatal(err)
	}
	var hit renewHit
	newToken := "hd_agentrenew_us_newtoken"
	srv := startRenewServer(t, newChain, newToken, &hit)
	defer srv.Close()

	dir := t.TempDir()
	oldToken := "hd_agentrenew_us_oldtoken"
	writeChain(t, dir, oldChain, oldToken)

	if err := MaybeRenew(srv.URL, dir); err != nil {
		t.Fatal(err)
	}
	if hit.path != "/v1/enroll/renew" {
		t.Fatalf("path=%q", hit.path)
	}
	if hit.body["renewal_token"] != oldToken {
		t.Fatalf("renewal_token=%q", hit.body["renewal_token"])
	}
	if hit.body["csr"] == "" || !strings.Contains(hit.body["csr"], "BEGIN CERTIFICATE REQUEST") {
		t.Fatal("expected csr")
	}
	if hit.body["certificate"] != "" {
		t.Fatal("token path must not send the leaf")
	}

	loaded, err := store.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.RenewalToken != newToken {
		t.Fatalf("persisted token=%q", loaded.RenewalToken)
	}
	gotCert, err := os.ReadFile(filepath.Join(dir, "client.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(gotCert), strings.TrimSpace(string(newChain.LeafPEM))) {
		t.Fatal("expected new leaf on disk")
	}
}

func TestMaybeRenewExpiredLeafStillRenewsWithToken(t *testing.T) {
	now := time.Now()
	expired, err := GenerateStepLikeChainWindow("agent-1", "org-1", now.Add(-40*24*time.Hour), now.Add(-20*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := GenerateStepLikeChain("agent-1", "org-1")
	if err != nil {
		t.Fatal(err)
	}
	var hit renewHit
	srv := startRenewServer(t, fresh, "hd_agentrenew_us_aftervacation", &hit)
	defer srv.Close()

	dir := t.TempDir()
	writeChain(t, dir, expired, "hd_agentrenew_us_vacation")

	if err := MaybeRenew(srv.URL, dir); err != nil {
		t.Fatal(err)
	}
	if hit.body["renewal_token"] != "hd_agentrenew_us_vacation" {
		t.Fatalf("expected token body, got %#v", hit.body)
	}
	if hit.body["certificate"] != "" {
		t.Fatal("vacation renew must not present the expired leaf")
	}
	loaded, err := store.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.RenewalToken != "hd_agentrenew_us_aftervacation" {
		t.Fatalf("token=%q", loaded.RenewalToken)
	}
}

func TestMaybeRenewNoTokenFallsBackToLeaf(t *testing.T) {
	now := time.Now()
	oldChain, err := GenerateStepLikeChainWindow("agent-1", "org-1", now.Add(-20*time.Hour), now.Add(4*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	newChain, err := GenerateStepLikeChain("agent-1", "org-1")
	if err != nil {
		t.Fatal(err)
	}
	var hit renewHit
	srv := startRenewServer(t, newChain, "hd_agentrenew_us_migrated", &hit)
	defer srv.Close()

	dir := t.TempDir()
	writeChain(t, dir, oldChain, "")

	if err := MaybeRenew(srv.URL, dir); err != nil {
		t.Fatal(err)
	}
	if hit.body["certificate"] == "" {
		t.Fatal("legacy path must send certificate")
	}
	if hit.body["renewal_token"] != "" {
		t.Fatalf("legacy path must not send renewal_token, got %q", hit.body["renewal_token"])
	}
	loaded, err := store.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.RenewalToken != "hd_agentrenew_us_migrated" {
		t.Fatalf("self-migrate token=%q", loaded.RenewalToken)
	}
}

func TestMaybeRenewBeforeHalfwayDoesNotPost(t *testing.T) {
	chain, err := GenerateStepLikeChain("agent-1", "org-1")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("should not POST before halfway")
	}))
	defer srv.Close()

	dir := t.TempDir()
	writeChain(t, dir, chain, "hd_agentrenew_us_unused")
	if err := MaybeRenew(srv.URL, dir); err != nil {
		t.Fatal(err)
	}
}

func TestPrintEnrollmentURL(t *testing.T) {
	var buf bytes.Buffer
	PrintEnrollmentURL(&buf, "https://app.hookdeploy.dev/app/cli-auth/s1")
	if !strings.Contains(buf.String(), "https://app.hookdeploy.dev/app/cli-auth/s1") {
		t.Fatalf("url not printed: %q", buf.String())
	}
}

func TestReadUserCode(t *testing.T) {
	var out bytes.Buffer
	code, err := ReadUserCode(strings.NewReader("abcd-2345\n"), &out)
	if err != nil {
		t.Fatal(err)
	}
	if code != "ABCD2345" {
		t.Fatalf("code=%q", code)
	}
	if !strings.Contains(out.String(), "Enter the code") {
		t.Fatalf("prompt=%q", out.String())
	}
}

func TestRequireInteractiveFilePipeFails(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	defer r.Close()
	err = RequireInteractiveFile(r)
	if err == nil || !strings.Contains(err.Error(), "not a TTY") {
		t.Fatalf("err=%v", err)
	}
}

func TestRunDevicePrintsURLStoresOrgNameAndSucceeds(t *testing.T) {
	chain, err := GenerateStepLikeChain("agent-1", "org-1")
	if err != nil {
		t.Fatal(err)
	}
	var startBody, pollBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/v1/enroll/device/start":
			_ = json.Unmarshal(raw, &startBody)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"session_id":       "s1",
				"device_code":      "dev",
				"verification_url": "https://app.hookdeploy.dev/app/cli-auth/s1",
				"interval":         1,
				"expires_in":       60,
			})
		case "/v1/enroll/device/poll":
			_ = json.Unmarshal(raw, &pollBody)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status":        "approved",
				"certificate":   string(chain.LeafPEM),
				"ca":            string(chain.IntermediatePEM),
				"certChain":     string(chain.CertChainPEM),
				"root":          string(chain.RootPEM),
				"agent_id":      "agent-1",
				"org_id":        "org-1",
				"org_name":      "Acme Corp",
				"org_slug":      "acme",
				"renewal_token": "hd_agentrenew_us_x",
			})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	var out bytes.Buffer
	var opened string
	if err := runDevice(srv.URL, dir, deviceIO{
		In:      strings.NewReader("ABCD-2345\n"),
		Out:     &out,
		OpenURL: func(u string) { opened = u },
		CheckInteractive: func() error {
			return nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok := startBody["org_hint"]; ok {
		t.Fatalf("start sent org_hint: %#v", startBody)
	}
	if pollBody["user_code"] != "ABCD2345" {
		t.Fatalf("poll body=%#v", pollBody)
	}
	if !strings.Contains(out.String(), "https://app.hookdeploy.dev/app/cli-auth/s1") {
		t.Fatalf("URL not printed: %q", out.String())
	}
	if !strings.Contains(out.String(), "enrolled in Acme Corp") {
		t.Fatalf("success did not name org: %q", out.String())
	}
	if opened != "https://app.hookdeploy.dev/app/cli-auth/s1" {
		t.Fatalf("opened=%q", opened)
	}
	orgDir := store.OrgDir(dir, "org-1")
	meta, err := store.LoadOrgMeta(orgDir)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Name != "Acme Corp" || meta.ID != "org-1" {
		t.Fatalf("meta=%#v", meta)
	}
	if _, err := store.Load(orgDir); err != nil {
		t.Fatalf("org dir: %v", err)
	}
	active, err := store.ReadActive(dir)
	if err != nil || active != "org-1" {
		t.Fatalf("active=%q err=%v", active, err)
	}
}
