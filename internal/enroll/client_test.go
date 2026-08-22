package enroll

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMintedParsesRenewalToken(t *testing.T) {
	raw := []byte(`{
		"certificate": "leaf",
		"ca": "intermediate",
		"certChain": "chain",
		"root": "root",
		"agent_id": "agent-1",
		"org_id": "org-1",
		"renewal_token": "hd_agentrenew_us_abcd"
	}`)
	var minted Minted
	if err := json.Unmarshal(raw, &minted); err != nil {
		t.Fatal(err)
	}
	if minted.RenewalToken != "hd_agentrenew_us_abcd" {
		t.Fatalf("RenewalToken=%q", minted.RenewalToken)
	}
	if minted.AgentID != "agent-1" || minted.OrgID != "org-1" {
		t.Fatalf("ids agent=%q org=%q", minted.AgentID, minted.OrgID)
	}
}

func TestMintedParsesOrgName(t *testing.T) {
	raw := []byte(`{
		"certificate": "leaf",
		"agent_id": "agent-1",
		"org_id": "org-1",
		"org_name": "Acme Corp",
		"org_slug": "acme"
	}`)
	var minted Minted
	if err := json.Unmarshal(raw, &minted); err != nil {
		t.Fatal(err)
	}
	if minted.OrgName != "Acme Corp" || minted.OrgSlug != "acme" {
		t.Fatalf("org name=%q slug=%q", minted.OrgName, minted.OrgSlug)
	}
}

func TestMintedMissingRenewalTokenIsEmpty(t *testing.T) {
	raw := []byte(`{
		"certificate": "leaf",
		"ca": "intermediate",
		"certChain": "chain",
		"root": "root",
		"agent_id": "agent-1",
		"org_id": "org-1"
	}`)
	var minted Minted
	if err := json.Unmarshal(raw, &minted); err != nil {
		t.Fatal(err)
	}
	if minted.RenewalToken != "" {
		t.Fatalf("RenewalToken=%q want empty", minted.RenewalToken)
	}
}

func TestClientRenewWithTokenPostsTokenNotLeaf(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"certificate":"leaf","ca":"ca","certChain":"chain","root":"root","renewal_token":"hd_agentrenew_us_next"}`))
	}))
	defer srv.Close()

	out, err := NewClient(srv.URL).RenewWithToken("hd_agentrenew_us_old", []byte("-----BEGIN CERTIFICATE REQUEST-----\nM\n-----END CERTIFICATE REQUEST-----"))
	if err != nil {
		t.Fatal(err)
	}
	if got["renewal_token"] != "hd_agentrenew_us_old" {
		t.Fatalf("body=%#v", got)
	}
	if _, ok := got["certificate"]; ok {
		t.Fatal("token renew must not send certificate")
	}
	if out.RenewalToken != "hd_agentrenew_us_next" {
		t.Fatalf("RenewalToken=%q", out.RenewalToken)
	}
}

func TestClientDeviceStartSendsHostname(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got)
		if r.URL.Path != "/v1/enroll/device/start" {
			t.Errorf("path=%s", r.URL.Path)
		}
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"session_id":"s1","device_code":"dev","verification_url":"https://app.example/app/cli-auth/s1","interval":5,"expires_in":600}`))
	}))
	defer srv.Close()
	if _, err := NewClient(srv.URL).DeviceStart("michaels-macbook"); err != nil {
		t.Fatal(err)
	}
	if _, ok := got["org_hint"]; ok {
		t.Fatalf("org_hint must be omitted, body=%#v", got)
	}
	if got["hostname"] != "michaels-macbook" {
		t.Fatalf("body=%#v", got)
	}
}

func TestClientDevicePollSendsUserCode(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got)
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"status":"pending","interval":1}`))
	}))
	defer srv.Close()
	if _, err := NewClient(srv.URL).DevicePoll("dev", "ABCD2345", nil); err != nil {
		t.Fatal(err)
	}
	if got["device_code"] != "dev" || got["user_code"] != "ABCD2345" {
		t.Fatalf("body=%#v", got)
	}
}

func TestClientTokenStartSendsHostnameNotName(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got)
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"status":"need_csr","agent_id":"a1","org_id":"o1"}`))
	}))
	defer srv.Close()
	if _, err := NewClient(srv.URL).TokenStart("hd_enroll_us_x", "prod.hookdeploy.dev"); err != nil {
		t.Fatal(err)
	}
	if got["token"] != "hd_enroll_us_x" || got["hostname"] != "prod.hookdeploy.dev" {
		t.Fatalf("body=%#v", got)
	}
	if _, ok := got["name"]; ok {
		t.Fatal("enroll must not send name")
	}
}

func TestClientRenewPostsCertificate(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got)
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"certificate":"leaf","ca":"ca","certChain":"chain","root":"root"}`))
	}))
	defer srv.Close()

	if _, err := NewClient(srv.URL).Renew([]byte("LEAF"), nil, []byte("ROOT"), []byte("CSR")); err != nil {
		t.Fatal(err)
	}
	if got["certificate"] != "LEAF" || got["csr"] != "CSR" {
		t.Fatalf("body=%#v", got)
	}
	if got["renewal_token"] != "" {
		t.Fatal("leaf renew must not send renewal_token")
	}
}

func TestPlacementPostsTokenAndRegion(t *testing.T) {
	var got map[string]string
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got)
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"hostname":"relay-us-east-01.hookdeploy.dev","region_key":"us-east","reason":"requested"}`))
	}))
	defer srv.Close()

	out, err := NewClient(srv.URL).Placement("hd_agentrenew_us_tok", "us-east")
	if err != nil {
		t.Fatal(err)
	}
	if path != "/v1/agents/placement" {
		t.Fatalf("path=%q", path)
	}
	if got["renewal_token"] != "hd_agentrenew_us_tok" || got["region"] != "us-east" {
		t.Fatalf("body=%#v", got)
	}
	if out.Hostname != "relay-us-east-01.hookdeploy.dev" || out.RegionKey != "us-east" {
		t.Fatalf("%+v", out)
	}
}
