package enroll

import (
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
