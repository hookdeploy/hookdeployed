package tap

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hookdeploy/hookdeployed/internal/enroll"
	"github.com/hookdeploy/hookdeployed/internal/mtls"
	"github.com/hookdeploy/hookdeployed/internal/store"
)

const testToken = "hd_agentrenew_us_tapfixture"
const testEndpointID = "11111111-2222-4333-8444-555555555555"
const testDestID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"

func startIDs(port int, path string) StartOpts {
	return StartOpts{EndpointID: testEndpointID, DestinationID: testDestID, Port: port, Path: path}
}

func seedActive(t *testing.T, token string) string {
	t.Helper()
	root := t.TempDir()
	pki, err := mtls.GenerateTestPKI()
	if err != nil {
		t.Fatal(err)
	}
	dir := store.OrgDir(root, mtls.TestClientOU)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pki.CACert.Raw})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pki.ClientCert.Raw})
	keyDER, err := x509.MarshalECPrivateKey(pki.ClientKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := store.Write(dir, caPEM, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	if token != "" {
		if err := os.WriteFile(filepath.Join(dir, "renewal.token"), []byte(token), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.WriteOrgMeta(dir, store.OrgMeta{ID: mtls.TestClientOU, Name: "Acme", Slug: "acme"}); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteActive(root, mtls.TestClientOU); err != nil {
		t.Fatal(err)
	}
	return root
}

type tapServer struct {
	targets    any
	taps       any
	create     any
	stop       any
	status     map[string]int
	bodies     map[string]map[string]any
	createErr  *enroll.APIError
	stopErr    *enroll.APIError
	listStatus int
}

func (s *tapServer) start(t *testing.T) *httptest.Server {
	t.Helper()
	if s.bodies == nil {
		s.bodies = map[string]map[string]any{}
	}
	if s.status == nil {
		s.status = map[string]int{}
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		s.bodies[r.URL.Path] = body
		w.Header().Set("content-type", "application/json")

		code := s.status[r.URL.Path]
		if code == 0 {
			code = 200
		}
		if r.URL.Path == CreatePath && s.createErr != nil {
			writeAPIError(w, s.createErr)
			return
		}
		if r.URL.Path == StopPath && s.stopErr != nil {
			writeAPIError(w, s.stopErr)
			return
		}
		w.WriteHeader(code)
		switch r.URL.Path {
		case TargetsPath:
			_ = json.NewEncoder(w).Encode(s.targets)
		case ListPath:
			if s.listStatus != 0 {
				return
			}
			_ = json.NewEncoder(w).Encode(s.taps)
		case CreatePath:
			_ = json.NewEncoder(w).Encode(s.create)
		case StopPath:
			_ = json.NewEncoder(w).Encode(s.stop)
		default:
			http.NotFound(w, r)
		}
	}))
}

func writeAPIError(w http.ResponseWriter, api *enroll.APIError) {
	w.Header().Set("content-type", "application/json")
	status := api.Status
	if status == 0 {
		status = 400
	}
	w.WriteHeader(status)
	payload := map[string]any{"error": api.Code, "message": api.Message}
	if len(api.Destinations) > 0 {
		payload["destinations"] = api.Destinations
	}
	_ = json.NewEncoder(w).Encode(payload)
}

func sampleEndpoints() []Endpoint {
	return []Endpoint{
		{
			ID:   "ep-orders",
			Slug: "orders",
			Name: "Orders",
			Destinations: []Destination{
				{ID: "dest-https", Name: "prod-https", DestinationType: "https"},
				{ID: "dest-agent", Name: "prod-agent", DestinationType: "agent"},
			},
		},
		{
			ID:           "ep-billing",
			Slug:         "billing",
			Name:         "Billing",
			Destinations: nil,
		},
	}
}

func TestFormatListRendersEndpointsAndEmptyDestinations(t *testing.T) {
	out := FormatList(sampleEndpoints(), nil)
	if !strings.Contains(out, "orders") {
		t.Fatalf("missing orders:\n%s", out)
	}
	if !strings.Contains(out, "ep-orders") {
		t.Fatalf("missing endpoint id:\n%s", out)
	}
	if !strings.Contains(out, "prod-https (https)") || !strings.Contains(out, "prod-agent (agent)") {
		t.Fatalf("missing dests:\n%s", out)
	}
	if !strings.Contains(out, "dest-https") || !strings.Contains(out, "dest-agent") {
		t.Fatalf("missing dest ids:\n%s", out)
	}
	if !strings.Contains(out, "billing") || !strings.Contains(out, "(no destinations)") {
		t.Fatalf("empty dests:\n%s", out)
	}
	if !strings.Contains(out, "RUNNING TAPS") || !strings.Contains(out, "(none)") {
		t.Fatalf("running section:\n%s", out)
	}
}

func TestFormatListNoEndpoints(t *testing.T) {
	out := FormatList(nil, nil)
	if !strings.Contains(out, "No endpoints in this organization.") {
		t.Fatalf("empty endpoints:\n%s", out)
	}
	if !strings.Contains(out, "RUNNING TAPS") {
		t.Fatalf("should still show running section:\n%s", out)
	}
}

func TestListCallsBothRoutesAndRenders(t *testing.T) {
	root := seedActive(t, testToken)
	srv := (&tapServer{
		targets: map[string]any{"endpoints": sampleEndpoints()},
		taps: map[string]any{"taps": []Tap{{
			ID:            "tap-live",
			EndpointID:    "ep-orders",
			DestinationID: strPtr("dest-https"),
			TargetPort:    3000,
			TargetPath:    "/hooks/stripe",
			ExpiresAt:     "2026-08-24T18:00:00.000Z",
		}}},
	}).start(t)
	defer srv.Close()

	var out bytes.Buffer
	if err := List(Config{
		Root:      root,
		EnrollURL: srv.URL,
		Stdout:    &out,
		Client:    enroll.NewClient(srv.URL),
	}); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, "orders") || !strings.Contains(got, "tap-live") {
		t.Fatalf("list output:\n%s", got)
	}
	if !strings.Contains(got, "ep-orders") {
		t.Fatalf("endpoint id in list:\n%s", got)
	}
	if !strings.Contains(got, "127.0.0.1:3000/hooks/stripe") {
		t.Fatalf("target:\n%s", got)
	}
	if !strings.Contains(got, "prod-https") {
		t.Fatalf("running tap should join dest name:\n%s", got)
	}
}

func strPtr(s string) *string { return &s }

func TestListReusesExplainResolveWhenNotEnrolled(t *testing.T) {
	err := List(Config{Root: t.TempDir(), Stdout: io.Discard})
	if err == nil || !strings.Contains(err.Error(), "run `agent enroll` first") {
		t.Fatalf("err=%v", err)
	}
}

func TestListReusesExplainResolveWhenNoActive(t *testing.T) {
	root := t.TempDir()
	seedOrgNoActive(t, root)
	err := List(Config{Root: root, Stdout: io.Discard})
	if err == nil || !strings.Contains(err.Error(), "no organization selected") {
		t.Fatalf("err=%v", err)
	}
	if !strings.Contains(err.Error(), "agent switch") {
		t.Fatalf("should reuse ExplainResolve: %v", err)
	}
}

func seedOrgNoActive(t *testing.T, root string) {
	t.Helper()
	pki, err := mtls.GenerateTestPKI()
	if err != nil {
		t.Fatal(err)
	}
	dir := store.OrgDir(root, mtls.TestClientOU)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pki.CACert.Raw})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pki.ClientCert.Raw})
	keyDER, err := x509.MarshalECPrivateKey(pki.ClientKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := store.Write(dir, caPEM, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteOrgMeta(dir, store.OrgMeta{ID: mtls.TestClientOU, Name: "Acme", Slug: "acme"}); err != nil {
		t.Fatal(err)
	}
}

func TestCreateSendsIdsPortPathAndToken(t *testing.T) {
	root := seedActive(t, testToken)
	fake := &tapServer{
		create: map[string]any{"tap": Tap{
			ID:         "tap-1",
			TargetPort: 3000,
			TargetPath: "/hooks/stripe",
			ExpiresAt:  "2026-08-24T18:00:00Z",
		}},
		stop: map[string]any{"tap": Tap{ID: "tap-1"}},
	}
	srv := fake.start(t)
	defer srv.Close()

	var out bytes.Buffer
	opts := startIDs(3000, "/hooks/stripe")
	opts.Duration = 2 * time.Hour
	err := Start(context.Background(), Config{
		Root:      root,
		EnrollURL: srv.URL,
		TTY:       true,
		Stdout:    &out,
		Client:    enroll.NewClient(srv.URL),
		Wait:      func(context.Context) error { return nil },
	}, opts)
	if err != nil {
		t.Fatal(err)
	}
	body := fake.bodies[CreatePath]
	if body["renewal_token"] != testToken {
		t.Fatalf("token=%v", body["renewal_token"])
	}
	if body["endpoint_id"] != testEndpointID || body["destination_id"] != testDestID {
		t.Fatalf("body=%v", body)
	}
	if body["target_port"] != float64(3000) || body["target_path"] != "/hooks/stripe" {
		t.Fatalf("target=%v", body)
	}
	if body["duration_seconds"] != float64(7200) {
		t.Fatalf("duration=%v", body["duration_seconds"])
	}
	printed := out.String()
	if !strings.Contains(printed, "Tapping "+testEndpointID+" / "+testDestID) {
		t.Fatalf("confirm:\n%s", printed)
	}
	if !strings.Contains(printed, "127.0.0.1:3000/hooks/stripe") {
		t.Fatalf("target line:\n%s", printed)
	}
	if !strings.Contains(printed, ConnectHint) {
		t.Fatalf("connect hint:\n%s", printed)
	}
	if !strings.Contains(printed, "Stopped tap tap-1.") {
		t.Fatalf("stop confirm:\n%s", printed)
	}
}

func TestCreateEndpointOnlyOmitsDestinationId(t *testing.T) {
	root := seedActive(t, testToken)
	fake := &tapServer{
		create: map[string]any{"tap": Tap{
			ID:            "tap-raw",
			EndpointID:    testEndpointID,
			DestinationID: nil,
			TargetPort:    3000,
			TargetPath:    "/hooks/raw",
			ExpiresAt:     "2026-08-24T18:00:00Z",
		}},
		stop: map[string]any{"tap": Tap{ID: "tap-raw"}},
	}
	srv := fake.start(t)
	defer srv.Close()

	var out bytes.Buffer
	err := Start(context.Background(), Config{
		Root:      root,
		EnrollURL: srv.URL,
		TTY:       true,
		Stdout:    &out,
		Client:    enroll.NewClient(srv.URL),
		Wait:      func(context.Context) error { return nil },
	}, StartOpts{EndpointID: testEndpointID, Port: 3000, Path: "/hooks/raw"})
	if err != nil {
		t.Fatal(err)
	}
	body := fake.bodies[CreatePath]
	if body["endpoint_id"] != testEndpointID {
		t.Fatalf("endpoint_id=%v", body["endpoint_id"])
	}
	if _, ok := body["destination_id"]; ok {
		t.Fatalf("endpoint-only create must omit destination_id, got %v", body["destination_id"])
	}
	printed := out.String()
	if !strings.Contains(printed, "Tapping "+testEndpointID+" / (endpoint)") {
		t.Fatalf("confirm:\n%s", printed)
	}
	if strings.Contains(printed, "Tapping "+testEndpointID+" /  ") {
		t.Fatalf("blank dest line:\n%s", printed)
	}
}

func TestMalformedIdRejectedClientSide(t *testing.T) {
	err := Start(context.Background(), Config{
		Root:   t.TempDir(),
		TTY:    true,
		Stdout: io.Discard,
		Wait:   func(context.Context) error { return errors.New("must not wait") },
	}, StartOpts{EndpointID: "orders", DestinationID: testDestID, Port: 3000, Path: "/hooks"})
	if err == nil || !strings.Contains(err.Error(), ErrNotUUID) {
		t.Fatalf("err=%v", err)
	}
	if !strings.Contains(err.Error(), "endpoint id") {
		t.Fatalf("should name the field: %v", err)
	}
}

func TestMalformedEndpointIdRejectedWithoutDestination(t *testing.T) {
	err := Start(context.Background(), Config{
		Root:   t.TempDir(),
		TTY:    true,
		Stdout: io.Discard,
		Wait:   func(context.Context) error { return errors.New("must not wait") },
	}, StartOpts{EndpointID: "orders", Port: 3000, Path: "/hooks"})
	if err == nil || !strings.Contains(err.Error(), ErrNotUUID) {
		t.Fatalf("err=%v", err)
	}
	if !strings.Contains(err.Error(), "endpoint id") {
		t.Fatalf("should name the field: %v", err)
	}
}

func TestWrongIdSurfacesServerError(t *testing.T) {
	root := seedActive(t, testToken)
	fake := &tapServer{
		createErr: &enroll.APIError{
			Status:  404,
			Code:    "not_found",
			Message: "No endpoint with that id in this organization.",
		},
	}
	srv := fake.start(t)
	defer srv.Close()

	err := Start(context.Background(), Config{
		Root:      root,
		EnrollURL: srv.URL,
		TTY:       true,
		Stdout:    io.Discard,
		Client:    enroll.NewClient(srv.URL),
		Wait:      func(context.Context) error { return errors.New("must not wait after 404") },
	}, startIDs(3000, "/hooks"))
	if err == nil {
		t.Fatal("expected server error")
	}
	if err.Error() != "No endpoint with that id in this organization." {
		t.Fatalf("err=%v", err)
	}
	if strings.Contains(err.Error(), ErrNotUUID) {
		t.Fatal("valid-shaped id must not use the client-side uuid message")
	}
}

func TestCtrlCCallsStop(t *testing.T) {
	root := seedActive(t, testToken)
	var stopped string
	fake := &tapServer{
		create: map[string]any{"tap": Tap{ID: "tap-ctrl", TargetPort: 9, TargetPath: "/", ExpiresAt: "2026-08-24T18:00:00Z"}},
		stop:   map[string]any{"tap": Tap{ID: "tap-ctrl"}},
	}
	srv := fake.start(t)
	defer srv.Close()

	err := Start(context.Background(), Config{
		Root:      root,
		EnrollURL: srv.URL,
		TTY:       true,
		Stdout:    io.Discard,
		Client:    enroll.NewClient(srv.URL),
		Wait: func(ctx context.Context) error {
			return nil
		},
		Stop: func(token, id string) error {
			if token != testToken {
				t.Fatalf("stop token=%q", token)
			}
			stopped = id
			return nil
		},
	}, startIDs(3000, "/x"))
	if err != nil {
		t.Fatal(err)
	}
	if stopped != "tap-ctrl" {
		t.Fatalf("stopped=%q", stopped)
	}
}

func TestFailedStopIsReported(t *testing.T) {
	root := seedActive(t, testToken)
	fake := &tapServer{
		create: map[string]any{"tap": Tap{
			ID:         "tap-linger",
			TargetPort: 3000,
			TargetPath: "/",
			ExpiresAt:  "2026-08-24T18:00:00Z",
		}},
	}
	srv := fake.start(t)
	defer srv.Close()

	err := Start(context.Background(), Config{
		Root:      root,
		EnrollURL: srv.URL,
		TTY:       true,
		Stdout:    io.Discard,
		Client:    enroll.NewClient(srv.URL),
		Wait:      func(context.Context) error { return nil },
		Stop: func(token, id string) error {
			return &enroll.APIError{Status: 502, Code: "upstream", Message: "connection refused"}
		},
	}, startIDs(3000, "/"))
	if err == nil {
		t.Fatal("expected failed stop")
	}
	msg := err.Error()
	if !strings.Contains(msg, "could not stop tap tap-linger: connection refused") {
		t.Fatalf("msg=%s", msg)
	}
	if !strings.Contains(msg, "still live") || !strings.Contains(msg, "2026-08-24 18:00 UTC") {
		t.Fatalf("linger=%s", msg)
	}
}

func TestNonTTYRefusesBeforeCreate(t *testing.T) {
	root := seedActive(t, testToken)
	fake := &tapServer{
		create: map[string]any{"tap": Tap{ID: "should-not"}},
	}
	srv := fake.start(t)
	defer srv.Close()

	err := Start(context.Background(), Config{
		Root:      root,
		EnrollURL: srv.URL,
		TTY:       false,
		Stdout:    io.Discard,
		Client:    enroll.NewClient(srv.URL),
		Wait: func(context.Context) error {
			t.Fatal("must not wait")
			return nil
		},
	}, startIDs(3000, "/"))
	if err == nil || err.Error() != NeedsTTY {
		t.Fatalf("err=%v", err)
	}
	if _, ok := fake.bodies[CreatePath]; ok {
		t.Fatal("must not create a tap without a TTY")
	}
}

func TestNoTTYStartsWithoutTTY(t *testing.T) {
	root := seedActive(t, testToken)
	fake := &tapServer{
		create: map[string]any{"tap": Tap{
			ID:         "tap-headless",
			TargetPort: 3000,
			TargetPath: "/hooks",
			ExpiresAt:  "2026-08-24T18:00:00Z",
		}},
		stop: map[string]any{"tap": Tap{ID: "tap-headless"}},
	}
	srv := fake.start(t)
	defer srv.Close()

	opts := startIDs(3000, "/hooks")
	opts.NoTTY = true
	var out bytes.Buffer
	err := Start(context.Background(), Config{
		Root:      root,
		EnrollURL: srv.URL,
		TTY:       false,
		Stdout:    &out,
		Client:    enroll.NewClient(srv.URL),
		Wait:      func(context.Context) error { return nil },
	}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if fake.bodies[CreatePath] == nil {
		t.Fatal("must create when -no-tty is set")
	}
	printed := out.String()
	wantCreate := FormatCreated(opts, Tap{TargetPort: 3000, TargetPath: "/hooks", ExpiresAt: "2026-08-24T18:00:00Z"})
	if !strings.Contains(printed, wantCreate) {
		t.Fatalf("create line must match interactive FormatCreated:\n%s\nwant:\n%s", printed, wantCreate)
	}
	if !strings.Contains(printed, ConnectHint) {
		t.Fatalf("connect hint:\n%s", printed)
	}
	if !strings.Contains(printed, "Stopped tap tap-headless.") {
		t.Fatalf("stop confirm must match interactive:\n%s", printed)
	}
	if strings.Contains(printed, StopHint) {
		t.Fatalf("headless must not print the Ctrl+C hint:\n%s", printed)
	}
	if !strings.Contains(printed, HeadlessHint) {
		t.Fatalf("headless hint:\n%s", printed)
	}
}

func TestNoTTYStdinCloseStops(t *testing.T) {
	root := seedActive(t, testToken)
	fake := &tapServer{
		create: map[string]any{"tap": Tap{
			ID:         "tap-eof",
			TargetPort: 9,
			TargetPath: "/",
			ExpiresAt:  "2026-08-24T18:00:00Z",
		}},
		stop: map[string]any{"tap": Tap{ID: "tap-eof"}},
	}
	srv := fake.start(t)
	defer srv.Close()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	opts := startIDs(9, "/")
	opts.NoTTY = true
	var out bytes.Buffer
	errCh := make(chan error, 1)
	go func() {
		errCh <- Start(context.Background(), Config{
			Root:      root,
			EnrollURL: srv.URL,
			TTY:       false,
			Stdin:     r,
			Stdout:    &out,
			Client:    enroll.NewClient(srv.URL),
		}, opts)
	}()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stdin close did not unblock Start")
	}
	if fake.bodies[StopPath]["tap_id"] != "tap-eof" {
		t.Fatalf("stop body=%v", fake.bodies[StopPath])
	}
	if !strings.Contains(out.String(), "Stopped tap tap-eof.") {
		t.Fatalf("stop confirm:\n%s", out.String())
	}
}

func TestEveryP1ErrorRendersItsMessage(t *testing.T) {
	cases := []struct {
		code    string
		status  int
		message string
	}{
		{"bad_request", 400, "renewal_token is required"},
		{"unauthorized", 401, "invalid renewal token"},
		{"unauthorized", 401, "renewal token reused"},
		{"unauthorized", 401, "renewal token revoked"},
		{"unauthorized", 401, "renewal token expired"},
		{"unauthorized", 401, "agent not found or revoked"},
		{"bad_request", 400, "endpoint_id is required"},
		{"bad_request", 400, "endpoint_id must be a UUID"},
		{"bad_request", 400, "destination_id must be a UUID"},
		{"bad_request", 400, "target_port must be an integer"},
		{"bad_request", 400, "A target port is required."},
		{"bad_request", 400, "Target port must be an integer between 1 and 65535."},
		{"bad_request", 400, "Port 22 is used by ssh and can't receive webhooks."},
		{"bad_request", 400, "target_path is required"},
		{"bad_request", 400, "Path must start with /."},
		{"bad_request", 400, "duration_seconds must be an integer"},
		{"not_found", 404, "No endpoint with that id in this organization."},
		{"not_found", 404, "No destination with that id on this endpoint."},
		{"bad_request", 400, "That destination does not belong to this endpoint."},
		{"conflict", 409, "This endpoint already has 5 live taps. Stop one before starting another."},
		{"bad_request", 400, "This agent is marked production and cannot be a tap target. Use a development agent."},
		{"not_found", 404, "No such tap."},
		{"forbidden", 403, "That destination is not in this organization."},
		{"taps_unavailable", 502, "Tap support is not available in this region yet."},
		{"misconfigured", 500, "tap rate limit is not configured"},
		{"rate_limited", 429, "tap rate limit exceeded (20/minute)"},
	}
	root := seedActive(t, testToken)
	for _, tc := range cases {
		t.Run(tc.message, func(t *testing.T) {
			fake := &tapServer{
				createErr: &enroll.APIError{Status: tc.status, Code: tc.code, Message: tc.message},
			}
			srv := fake.start(t)
			defer srv.Close()
			err := Start(context.Background(), Config{
				Root:      root,
				EnrollURL: srv.URL,
				TTY:       true,
				Stdout:    io.Discard,
				Client:    enroll.NewClient(srv.URL),
			}, startIDs(3000, "/"))
			if err == nil || err.Error() != tc.message {
				t.Fatalf("err=%v want %q", err, tc.message)
			}
		})
	}
}

func TestStopNoArgStopsTheOnlyTap(t *testing.T) {
	root := seedActive(t, testToken)
	fake := &tapServer{
		taps: map[string]any{"taps": []Tap{{ID: "only-tap"}}},
		stop: map[string]any{"tap": Tap{ID: "only-tap"}},
	}
	srv := fake.start(t)
	defer srv.Close()
	var out bytes.Buffer
	if err := Stop(Config{
		Root:      root,
		EnrollURL: srv.URL,
		Stdout:    &out,
		Client:    enroll.NewClient(srv.URL),
	}, ""); err != nil {
		t.Fatal(err)
	}
	if fake.bodies[StopPath]["tap_id"] != "only-tap" {
		t.Fatalf("stop body=%v", fake.bodies[StopPath])
	}
	if !strings.Contains(out.String(), "Stopped tap only-tap.") {
		t.Fatalf("out=%s", out.String())
	}
}

func TestStopNoArgRefusesWhenMultiple(t *testing.T) {
	root := seedActive(t, testToken)
	fake := &tapServer{
		taps: map[string]any{"taps": []Tap{{ID: "tap-a"}, {ID: "tap-b"}}},
	}
	srv := fake.start(t)
	defer srv.Close()
	err := Stop(Config{
		Root:      root,
		EnrollURL: srv.URL,
		Stdout:    io.Discard,
		Client:    enroll.NewClient(srv.URL),
	}, "")
	if err == nil || !strings.Contains(err.Error(), "multiple taps are running") {
		t.Fatalf("err=%v", err)
	}
	if !strings.Contains(err.Error(), "tap-a") || !strings.Contains(err.Error(), "tap-b") {
		t.Fatalf("ids: %v", err)
	}
	if _, ok := fake.bodies[StopPath]; ok {
		t.Fatal("must not stop when multiple")
	}
}

func TestStopNoArgWhenNone(t *testing.T) {
	root := seedActive(t, testToken)
	fake := &tapServer{taps: map[string]any{"taps": []Tap{}}}
	srv := fake.start(t)
	defer srv.Close()
	err := Stop(Config{
		Root:      root,
		EnrollURL: srv.URL,
		Stdout:    io.Discard,
		Client:    enroll.NewClient(srv.URL),
	}, "")
	if err == nil || err.Error() != "No running taps." {
		t.Fatalf("err=%v", err)
	}
}

func TestStopAlreadyEndedRendersNoSuchTapUnchanged(t *testing.T) {
	root := seedActive(t, testToken)
	fake := &tapServer{
		stopErr: &enroll.APIError{Status: 404, Code: "not_found", Message: "No such tap."},
	}
	srv := fake.start(t)
	defer srv.Close()
	err := Stop(Config{
		Root:      root,
		EnrollURL: srv.URL,
		Stdout:    io.Discard,
		Client:    enroll.NewClient(srv.URL),
	}, "someone-elses-tap")
	if err == nil || err.Error() != "No such tap." {
		t.Fatalf("err=%v", err)
	}
}

func TestParseStartFlagsAnywhere(t *testing.T) {
	fs := flag.NewFlagSet("tap", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	opts, err := ParseStartFlags(fs, []string{testEndpointID, testDestID, "-port", "3000", "-path", "/hooks/stripe", "-duration", "1h"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.EndpointID != testEndpointID || opts.DestinationID != testDestID || opts.Port != 3000 || opts.Path != "/hooks/stripe" || opts.Duration != time.Hour {
		t.Fatalf("%+v", opts)
	}
}

func TestParseStartFlagsOnePositional(t *testing.T) {
	fs := flag.NewFlagSet("tap", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	opts, err := ParseStartFlags(fs, []string{testEndpointID, "-port", "3000", "-path", "/hooks/raw"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.EndpointID != testEndpointID || opts.DestinationID != "" || opts.Port != 3000 || opts.Path != "/hooks/raw" {
		t.Fatalf("%+v", opts)
	}
}

func TestParseStartFlagsNoTTY(t *testing.T) {
	fs := flag.NewFlagSet("tap", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	opts, err := ParseStartFlags(fs, []string{testEndpointID, "-port", "3000", "-path", "/x", "-no-tty"})
	if err != nil {
		t.Fatal(err)
	}
	if !opts.NoTTY || opts.EndpointID != testEndpointID || opts.Port != 3000 || opts.Path != "/x" {
		t.Fatalf("%+v", opts)
	}

	fs2 := flag.NewFlagSet("tap", flag.ContinueOnError)
	fs2.SetOutput(io.Discard)
	opts2, err := ParseStartFlags(fs2, []string{"-no-tty", testEndpointID, testDestID, "-port", "9", "-path", "/"})
	if err != nil {
		t.Fatal(err)
	}
	if !opts2.NoTTY || opts2.EndpointID != testEndpointID || opts2.DestinationID != testDestID {
		t.Fatalf("bool flag must not consume the next arg: %+v", opts2)
	}
}

func TestCreateDoesNotRotateToken(t *testing.T) {
	root := seedActive(t, testToken)
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if strings.Contains(r.URL.Path, "renew") {
			t.Fatal("tap must never call renew")
		}
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case CreatePath:
			_ = json.NewEncoder(w).Encode(map[string]any{"tap": Tap{ID: "tap-1", TargetPort: 1, TargetPath: "/", ExpiresAt: "2026-08-24T18:00:00Z"}})
		case StopPath:
			_ = json.NewEncoder(w).Encode(map[string]any{"tap": Tap{ID: "tap-1"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	if err := Start(context.Background(), Config{
		Root:      root,
		EnrollURL: srv.URL,
		TTY:       true,
		Stdout:    io.Discard,
		Client:    enroll.NewClient(srv.URL),
		Wait:      func(context.Context) error { return nil },
	}, startIDs(3000, "/")); err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		if strings.Contains(p, "renew") {
			t.Fatalf("renew path %s", p)
		}
	}
}

func TestFormatCreatedUsesServerExpiresAt(t *testing.T) {
	got := FormatCreated(startIDs(3000, "/x"), Tap{
		TargetPort: 3000,
		TargetPath: "/x",
		ExpiresAt:  "2026-08-24T18:00:00Z",
	})
	if !strings.Contains(got, "Expires 2026-08-24 18:00 UTC") {
		t.Fatalf("%s", got)
	}
}

func TestFormatCreatedEndpointOnly(t *testing.T) {
	got := FormatCreated(StartOpts{EndpointID: testEndpointID, Port: 3000, Path: "/x"}, Tap{
		TargetPort: 3000,
		TargetPath: "/x",
		ExpiresAt:  "2026-08-24T18:00:00Z",
	})
	if !strings.Contains(got, "Tapping "+testEndpointID+" / (endpoint) →") {
		t.Fatalf("%s", got)
	}
	if strings.Contains(got, " /  ") {
		t.Fatalf("blank dest: %s", got)
	}
}

func TestWrapAPIErrorFallsBackToCode(t *testing.T) {
	err := wrapAPIError(&enroll.APIError{Code: "internal_error"})
	if err.Error() != "internal_error" {
		t.Fatalf("%v", err)
	}
}

func TestFailedStopDoesNotIncludePayload(t *testing.T) {
	err := failedStopError(Tap{ID: "tap-x", ExpiresAt: "2026-08-24T18:00:00Z"}, fmt.Errorf("agent_not_connected"))
	if strings.Contains(err.Error(), "{") || strings.Contains(err.Error(), "body") {
		t.Fatalf("payload leak: %s", err)
	}
}
