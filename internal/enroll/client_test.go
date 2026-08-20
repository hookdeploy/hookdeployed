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
