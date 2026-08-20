package enroll

import (
	"encoding/json"
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
