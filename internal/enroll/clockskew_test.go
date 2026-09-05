package enroll

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNoteResponseDateDetectsExcessiveSkew(t *testing.T) {
	ResetObservedClockSkew()
	defer ResetObservedClockSkew()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Server claims "now" is 20 minutes behind the real local clock we pass in.
		w.Header().Set("Date", time.Now().UTC().Add(-20*time.Minute).Format(http.TimeFormat))
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"error":"unauthorized","message":"renewal token expired"}`))
	}))
	defer srv.Close()

	_, err := NewClient(srv.URL).TokenStart("hd_enroll_us_x", "box")
	if err == nil {
		t.Fatal("expected error")
	}
	if !ExcessiveClockSkew() {
		skew, ok := ObservedClockSkew()
		t.Fatalf("expected excessive skew, got skew=%s ok=%v", skew, ok)
	}
	skew, _ := ObservedClockSkew()
	if skew < 15*time.Minute {
		t.Fatalf("skew=%s want ~20m local-ahead", skew)
	}
}

func TestNoteResponseDateWithinThresholdNotExcessive(t *testing.T) {
	ResetObservedClockSkew()
	defer ResetObservedClockSkew()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Date", time.Now().UTC().Add(30*time.Second).Format(http.TimeFormat))
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"hostname":"relay.example","region_key":"us-east"}`))
	}))
	defer srv.Close()

	_, err := NewClient(srv.URL).Placement("hd_agentrenew_us_tok", PlacementOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if ExcessiveClockSkew() {
		skew, _ := ObservedClockSkew()
		t.Fatalf("30s skew should not be excessive: %s", skew)
	}
}

func TestIsDeadCredentialVocabulary(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
	}{
		{"renewal token expired", true},
		{"renewal token revoked", true},
		{"renewal token reused", true},
		{"invalid renewal token", true},
		{"agent not found or revoked", true},
		{"placement rate limit exceeded (20/minute)", false},
		{"no healthy relay is available", false},
		{"token already consumed", false},
	}
	for _, tc := range cases {
		err := &APIError{Status: 401, Code: "unauthorized", Message: tc.msg}
		if got := IsDeadCredential(err); got != tc.want {
			t.Fatalf("%q: got %v want %v", tc.msg, got, tc.want)
		}
	}
}
