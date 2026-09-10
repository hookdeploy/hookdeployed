package enroll

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Fixture responses mirror enrollment-worker HttpError envelopes:
// { "error": "<code>", "message": "<text>" }.

func writeErr(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   code,
		"message": message,
	})
}

func TestTokenAlreadyConsumedFailsOnceDistinctly(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/v1/enroll/token" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		writeErr(w, 401, "unauthorized", "token already consumed")
	}))
	defer srv.Close()

	_, err := NewClient(srv.URL).TokenStart("hd_enroll_us_used", "box")
	if err == nil {
		t.Fatal("expected error")
	}
	var api *APIError
	if !errors.As(err, &api) {
		t.Fatalf("want APIError, got %T %v", err, err)
	}
	if api.Status != 401 || api.Code != "unauthorized" || api.Message != "token already consumed" {
		t.Fatalf("api=%+v", api)
	}
	if err.Error() != "token already consumed" {
		t.Fatalf("user-facing Error()=%q", err.Error())
	}
	if hits.Load() != 1 {
		t.Fatalf("hits=%d want exactly 1 (no client retry)", hits.Load())
	}
}

func TestTokenExpiredFailsOnceDistinctly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, 401, "unauthorized", "token expired")
	}))
	defer srv.Close()

	_, err := NewClient(srv.URL).TokenStart("hd_enroll_us_old", "box")
	if err == nil || err.Error() != "token expired" {
		t.Fatalf("err=%v", err)
	}
	var api *APIError
	if !errors.As(err, &api) || api.Message == "token already consumed" {
		t.Fatalf("expired must not look like consumed: %+v", api)
	}
}

func TestTokenInvalidFailsOnceDistinctly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, 401, "unauthorized", "invalid token")
	}))
	defer srv.Close()

	_, err := NewClient(srv.URL).TokenStart("hd_enroll_us_bad", "box")
	if err == nil || err.Error() != "invalid token" {
		t.Fatalf("err=%v", err)
	}
}

func TestRenewalTokenExpiredSurfacesMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/enroll/renew" {
			t.Errorf("path=%s", r.URL.Path)
		}
		writeErr(w, 401, "unauthorized", "renewal token expired")
	}))
	defer srv.Close()

	_, err := NewClient(srv.URL).RenewWithToken("hd_agentrenew_us_dead", []byte("-----BEGIN CERTIFICATE REQUEST-----\nM\n-----END CERTIFICATE REQUEST-----"))
	if err == nil || err.Error() != "renewal token expired" {
		t.Fatalf("err=%v", err)
	}
	var api *APIError
	if !errors.As(err, &api) || api.Status != 401 {
		t.Fatalf("api=%+v", api)
	}
}

func TestRenewalTokenRevokedSurfacesMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, 401, "unauthorized", "renewal token revoked")
	}))
	defer srv.Close()

	_, err := NewClient(srv.URL).RenewWithToken("hd_agentrenew_us_rev", []byte("-----BEGIN CERTIFICATE REQUEST-----\nM\n-----END CERTIFICATE REQUEST-----"))
	if err == nil || err.Error() != "renewal token revoked" {
		t.Fatalf("err=%v", err)
	}
}

func TestPlacementRateLimitedDistinctFromAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, 429, "rate_limited", "placement rate limit exceeded (20/minute)")
	}))
	defer srv.Close()

	_, err := NewClient(srv.URL).Placement("hd_agentrenew_us_tok", PlacementOptions{Region: "us-east"})
	if err == nil {
		t.Fatal("expected error")
	}
	var api *APIError
	if !errors.As(err, &api) {
		t.Fatalf("want APIError, got %v", err)
	}
	if api.Status != 429 || api.Code != "rate_limited" {
		t.Fatalf("rate limit must not look like 401 auth: %+v", api)
	}
	if err.Error() != "placement rate limit exceeded (20/minute)" {
		t.Fatalf("Error()=%q", err.Error())
	}
	if api.Code == "unauthorized" {
		t.Fatal("rate_limited must not collapse into unauthorized")
	}
}

func TestCertNotYetValidDistinctFromExpired(t *testing.T) {
	cases := []struct {
		name string
		msg  string
	}{
		{"not_yet_valid", "certificate not yet valid"},
		{"expired", "certificate expired"},
	}
	csr := []byte("-----BEGIN CERTIFICATE REQUEST-----\nM\n-----END CERTIFICATE REQUEST-----")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeErr(w, 401, "unauthorized", tc.msg)
			}))
			defer srv.Close()
			_, err := NewClient(srv.URL).Renew([]byte("leaf"), []byte("ca"), []byte("root"), csr)
			if err == nil || err.Error() != tc.msg {
				t.Fatalf("err=%v want %q", err, tc.msg)
			}
		})
	}
}

func TestDevicePollExpiredStatusFailsCleanly(t *testing.T) {
	var polls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/enroll/device/start":
			w.Header().Set("content-type", "application/json")
			_, _ = w.Write([]byte(`{"session_id":"s1","device_code":"dev","verification_url":"https://app.example/app/cli-auth/s1","interval":1,"expires_in":600}`))
		case "/v1/enroll/device/poll":
			polls.Add(1)
			w.Header().Set("content-type", "application/json")
			_, _ = w.Write([]byte(`{"status":"expired","interval":1}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	err := runDevice(srv.URL, t.TempDir(), deviceIO{
		In:      strings.NewReader("ABCD1234\n"),
		Out:     io.Discard,
		OpenURL: func(string) {},
	})
	if err == nil || err.Error() != "enrollment expired" {
		t.Fatalf("err=%v", err)
	}
	if polls.Load() != 1 {
		t.Fatalf("polls=%d want 1 (expired must not keep polling)", polls.Load())
	}
}

func TestDevicePollConsumedStatusFailsCleanly(t *testing.T) {
	var polls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/enroll/device/start":
			w.Header().Set("content-type", "application/json")
			_, _ = w.Write([]byte(`{"session_id":"s1","device_code":"dev","verification_url":"https://app.example/app/cli-auth/s1","interval":1,"expires_in":600}`))
		case "/v1/enroll/device/poll":
			polls.Add(1)
			w.Header().Set("content-type", "application/json")
			_, _ = w.Write([]byte(`{"status":"consumed","interval":1}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	err := runDevice(srv.URL, t.TempDir(), deviceIO{
		In:      strings.NewReader("ABCD1234\n"),
		Out:     io.Discard,
		OpenURL: func(string) {},
	})
	if err == nil || err.Error() != "enrollment already completed" {
		t.Fatalf("err=%v", err)
	}
	if err.Error() == "enrollment expired" || err.Error() == "token already consumed" {
		t.Fatalf("consumed must not reuse expired/token-consumed copy: %v", err)
	}
	if polls.Load() != 1 {
		t.Fatalf("polls=%d want 1 (consumed must not keep polling)", polls.Load())
	}
}

func TestDevicePollDeniedFailsCleanly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/enroll/device/start":
			w.Header().Set("content-type", "application/json")
			_, _ = w.Write([]byte(`{"session_id":"s1","device_code":"dev","verification_url":"https://app.example/app/cli-auth/s1","interval":1,"expires_in":600}`))
		case "/v1/enroll/device/poll":
			w.Header().Set("content-type", "application/json")
			_, _ = w.Write([]byte(`{"status":"denied","interval":1}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	err := runDevice(srv.URL, t.TempDir(), deviceIO{
		In:      strings.NewReader("ABCD1234\n"),
		Out:     io.Discard,
		OpenURL: func(string) {},
	})
	if err == nil || err.Error() != "enrollment denied" {
		t.Fatalf("err=%v", err)
	}
}

func TestDeviceEnrollmentDeadlineExpiresWithoutIndefiniteHang(t *testing.T) {
	var polls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/enroll/device/start":
			w.Header().Set("content-type", "application/json")
			// expires_in=1 forces the client deadline to ~1s.
			_, _ = w.Write([]byte(`{"session_id":"s1","device_code":"dev","verification_url":"https://app.example/app/cli-auth/s1","interval":1,"expires_in":1}`))
		case "/v1/enroll/device/poll":
			polls.Add(1)
			w.Header().Set("content-type", "application/json")
			_, _ = w.Write([]byte(`{"status":"pending","interval":1}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	start := time.Now()
	err := runDevice(srv.URL, t.TempDir(), deviceIO{
		In:      strings.NewReader("ABCD1234\n"),
		Out:     io.Discard,
		OpenURL: func(string) {},
	})
	elapsed := time.Since(start)
	if err == nil || err.Error() != "enrollment expired" {
		t.Fatalf("err=%v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("deadline hang: elapsed=%s polls=%d", elapsed, polls.Load())
	}
	if polls.Load() < 1 {
		t.Fatal("expected at least one pending poll before deadline")
	}
}

func TestNetworkUnreachableIsNotAPIError(t *testing.T) {
	// Closed port — distinct from auth APIError envelopes.
	_, err := NewClient("http://127.0.0.1:1").TokenStart("hd_enroll_us_x", "box")
	if err == nil {
		t.Fatal("expected dial error")
	}
	var api *APIError
	if errors.As(err, &api) {
		t.Fatalf("network failure must not parse as APIError: %+v", api)
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "refused") && !strings.Contains(msg, "connect") && !strings.Contains(msg, "actively refused") {
		// OS wording varies; just ensure it is not an auth phrase.
		if strings.Contains(msg, "token") || strings.Contains(msg, "unauthorized") {
			t.Fatalf("network err looks like auth: %v", err)
		}
	}
}

func TestShouldRenewTreatsNotYetValidAsRenewNeeded(t *testing.T) {
	now := time.Now()
	future, err := GenerateStepLikeChainWindow("cn", "ou", now.Add(2*time.Hour), now.Add(26*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !ShouldRenew(future.Leaf, now) {
		t.Fatal("clock-skew not-yet-valid cert must trigger renew attempt")
	}
}
