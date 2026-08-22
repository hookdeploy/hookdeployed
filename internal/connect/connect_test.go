package connect

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hookdeploy/hookdeployed/internal/enroll"
	"github.com/hookdeploy/hookdeployed/internal/mtls"
	"github.com/hookdeploy/hookdeployed/internal/store"
	"github.com/hookdeploy/hookdeployed/internal/sysinfo"
)

func TestParseRelay(t *testing.T) {
	cases := []struct {
		in, host, addr string
	}{
		{"relay.example.com", "relay.example.com", "relay.example.com:9443"},
		{"relay.example.com:9443", "relay.example.com", "relay.example.com:9443"},
		{"relay.example.com:1234", "relay.example.com", "relay.example.com:1234"},
		{"127.0.0.1", "127.0.0.1", "127.0.0.1:9443"},
		{"127.0.0.1:9443", "127.0.0.1", "127.0.0.1:9443"},
	}
	for _, tc := range cases {
		host, addr, err := ParseRelay(tc.in)
		if err != nil {
			t.Fatalf("%q: %v", tc.in, err)
		}
		if host != tc.host || addr != tc.addr {
			t.Fatalf("%q: host=%q addr=%q want host=%q addr=%q", tc.in, host, addr, tc.host, tc.addr)
		}
	}
	if _, _, err := ParseRelay(""); err == nil {
		t.Fatal("empty relay should fail")
	}
}

func TestNextBackoff(t *testing.T) {
	got := []time.Duration{}
	var d time.Duration
	for i := 0; i < 7; i++ {
		d = NextBackoff(d)
		got = append(got, d)
	}
	want := []time.Duration{
		time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second,
		16 * time.Second, 30 * time.Second, 30 * time.Second,
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("backoff[%d]=%s want %s (all=%v)", i, got[i], want[i], got)
		}
	}
}

func TestIsWakeEvent(t *testing.T) {
	interval := 10 * time.Second
	base := time.Unix(1_700_000_000, 0) // wall time, no monotonic
	cases := []struct {
		name string
		last time.Time
		now  time.Time
		want bool
	}{
		{name: "zero last", last: time.Time{}, now: base, want: false},
		{name: "same instant", last: base, now: base, want: false},
		{name: "one interval", last: base, now: base.Add(interval), want: false},
		{name: "exactly 2x", last: base, now: base.Add(2 * interval), want: false},
		{name: "just over 2x", last: base, now: base.Add(2*interval + time.Nanosecond), want: true},
		{name: "hours of sleep", last: base, now: base.Add(10 * time.Hour), want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsWakeEvent(tc.last, tc.now, interval)
			if got != tc.want {
				t.Fatalf("IsWakeEvent(%s, %s, %s)=%v want %v", tc.last, tc.now, interval, got, tc.want)
			}
		})
	}
	if IsWakeEvent(base, base.Add(time.Hour), 0) {
		t.Fatal("zero interval must not be a wake")
	}
}

func TestIsWakeEventUsesWallNotMonotonic(t *testing.T) {
	interval := 10 * time.Second
	// Two Times with identical monotonic-stripped unix seconds far apart.
	last := time.Unix(1_000, 0)
	now := time.Unix(1_000, 0).Add(time.Hour)
	if !IsWakeEvent(last, now, interval) {
		t.Fatal("wall-clock hour gap should be a wake even if constructed as Unix times")
	}
}

func TestRunMissingCertDir(t *testing.T) {
	dir := t.TempDir()
	err := Run(context.Background(), Config{
		Relay:     "relay.example.com",
		CertsDir:  filepath.Join(dir, "missing"),
		EnrollURL: "http://127.0.0.1:1",
	})
	if err == nil {
		t.Fatal("expected missing cert error")
	}
	if !strings.Contains(err.Error(), "no enrolled cert in") {
		t.Fatalf("err=%q want 'no enrolled cert in'", err)
	}
	if !strings.Contains(err.Error(), "agent enroll") {
		t.Fatalf("err=%q should tell the user to enroll", err)
	}
}

func TestRunNoActiveListsOrgsAndAsksToSwitch(t *testing.T) {
	pki, err := mtls.GenerateTestPKI()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := writeEnrolled(store.OrgDir(root, "org-a"), pki); err != nil {
		t.Fatal(err)
	}
	if err := writeEnrolled(store.OrgDir(root, "org-b"), pki); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteOrgMeta(store.OrgDir(root, "org-a"), store.OrgMeta{ID: "org-a", Name: "Alpha", Slug: "alpha"}); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteOrgMeta(store.OrgDir(root, "org-b"), store.OrgMeta{ID: "org-b", Name: "Beta", Slug: "beta"}); err != nil {
		t.Fatal(err)
	}

	err = Run(context.Background(), Config{
		Relay:     "relay.example.com",
		CertsDir:  root,
		EnrollURL: "http://127.0.0.1:1",
	})
	if err == nil {
		t.Fatal("expected no-active error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "no organization selected") {
		t.Fatalf("err=%q", msg)
	}
	if !strings.Contains(msg, "agent switch") {
		t.Fatalf("err=%q should tell the user to switch", msg)
	}
	if !strings.Contains(msg, "org-a") || !strings.Contains(msg, "org-b") {
		t.Fatalf("err=%q should list remaining orgs", msg)
	}
	if strings.Contains(msg, "agent enroll") {
		t.Fatalf("must not look unenrolled: %q", msg)
	}
}

func TestConnectHandshakeAndTwoPings(t *testing.T) {
	pki, err := mtls.GenerateTestPKI()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := writeEnrolled(dir, pki); err != nil {
		t.Fatal(err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", pki.ServerTLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var pings atomic.Int32
	gotTwo := make(chan struct{})
	go servePings(ln, &pings, gotTwo)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, Config{
			Relay:        ln.Addr().String(),
			CertsDir:     dir,
			EnrollURL:    "http://127.0.0.1:1",
			PingInterval: 40 * time.Millisecond,
		})
	}()

	select {
	case <-gotTwo:
	case err := <-errCh:
		t.Fatalf("connect exited before 2 PINGs: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for 2 PINGs; saw %d", pings.Load())
	}
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("clean shutdown: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("connect did not exit after cancel")
	}
	if pings.Load() < 2 {
		t.Fatalf("pings=%d want >= 2", pings.Load())
	}
}

func TestReportRunsBeforeRenewAndFailureDoesNotBlockDial(t *testing.T) {
	pki, err := mtls.GenerateTestPKI()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := writeEnrolled(dir, pki); err != nil {
		t.Fatal(err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", pki.ServerTLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var pings atomic.Int32
	gotTwo := make(chan struct{})
	go servePings(ln, &pings, gotTwo)

	var order []string
	var mu sync.Mutex
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, Config{
			Relay:         ln.Addr().String(),
			CertsDir:      dir,
			EnrollURL:     "http://127.0.0.1:1",
			PingInterval:  40 * time.Millisecond,
			RenewInterval: time.Hour,
			Report: func(enrollURL, certDir string) error {
				mu.Lock()
				order = append(order, "report")
				mu.Unlock()
				return fmt.Errorf("forced report failure")
			},
			Renew: func(enrollURL, certDir string) error {
				mu.Lock()
				order = append(order, "renew")
				mu.Unlock()
				return nil
			},
		})
	}()

	select {
	case <-gotTwo:
	case err := <-errCh:
		t.Fatalf("connect exited before 2 PINGs: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for 2 PINGs; saw %d", pings.Load())
	}
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("clean shutdown: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("connect did not exit after cancel")
	}
	mu.Lock()
	got := append([]string(nil), order...)
	mu.Unlock()
	if len(got) < 2 || got[0] != "report" || got[1] != "renew" {
		t.Fatalf("order=%v want report then renew", got)
	}
	if pings.Load() < 2 {
		t.Fatalf("pings=%d want >= 2 (failed report must not block dial)", pings.Load())
	}
}

func TestFailedRenewDoesNotBlockDial(t *testing.T) {
	pki, err := mtls.GenerateTestPKI()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := writeEnrolled(dir, pki); err != nil {
		t.Fatal(err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", pki.ServerTLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var pings atomic.Int32
	gotTwo := make(chan struct{})
	go servePings(ln, &pings, gotTwo)

	var renews atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, Config{
			Relay:         ln.Addr().String(),
			CertsDir:      dir,
			EnrollURL:     "http://127.0.0.1:1",
			PingInterval:  40 * time.Millisecond,
			RenewInterval: time.Hour,
			Renew: func(enrollURL, certDir string) error {
				renews.Add(1)
				return fmt.Errorf("forced renew failure")
			},
		})
	}()

	select {
	case <-gotTwo:
	case err := <-errCh:
		t.Fatalf("connect exited before 2 PINGs: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for 2 PINGs; saw %d", pings.Load())
	}
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("clean shutdown: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("connect did not exit after cancel")
	}
	if renews.Load() < 1 {
		t.Fatal("expected MaybeRenew to be attempted before dial")
	}
	if pings.Load() < 2 {
		t.Fatalf("pings=%d want >= 2 (failed renew must not block dial)", pings.Load())
	}
}

func servePings(ln net.Listener, pings *atomic.Int32, gotTwo chan struct{}) {
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	reader := bufio.NewReader(tlsConn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		if trimHeartbeat(line) != "PING" {
			continue
		}
		if _, err := io.WriteString(tlsConn, "PONG\n"); err != nil {
			return
		}
		if pings.Add(1) == 2 {
			select {
			case <-gotTwo:
			default:
				close(gotTwo)
			}
		}
	}
}

func writeEnrolled(dir string, pki *mtls.PKI) error {
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pki.CACert.Raw})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pki.ClientCert.Raw})
	keyPEM, err := enroll.EncodeKey(pki.ClientKey)
	if err != nil {
		return err
	}
	return store.Write(dir, caPEM, certPEM, keyPEM)
}

func writeFullEnrollment(t *testing.T, dir string, pki *mtls.PKI) {
	t.Helper()
	if err := writeEnrolled(dir, pki); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "renewal.token"), []byte("hd_agentrenew_us_test"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sysinfo.StatePath(dir), []byte(`{"agent_id":"old"}`), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestParseRejectAndUnknownType(t *testing.T) {
	if reason, ok := parseReject(`{"type":"reject","reason":"revoked"}`); !ok || reason != "revoked" {
		t.Fatalf("revoked: reason=%q ok=%v", reason, ok)
	}
	if reason, ok := parseReject(`{"type":"reject","reason":"draining"}`); !ok || reason != "draining" {
		t.Fatalf("draining: reason=%q ok=%v", reason, ok)
	}
	if _, ok := parseReject(`{"type":"other","reason":"revoked"}`); ok {
		t.Fatal("unknown type must be ignored")
	}
	if _, ok := parseReject("PONG"); ok {
		t.Fatal("PONG is not a reject")
	}
	if err := classifyServerLine("PONG\n"); err != nil {
		t.Fatalf("PONG: %v", err)
	}
	if err := classifyServerLine(`{"type":"noop"}` + "\n"); err == nil || err.Error() != "heartbeat: expected PONG" {
		t.Fatalf("unknown type should look like a bad heartbeat, got %v", err)
	}
}

func TestRejectFrameIsNewlineDelimitedJSON(t *testing.T) {
	frame := `{"type":"reject","reason":"revoked"}` + "\n"
	if !strings.HasSuffix(frame, "\n") || strings.Count(frame, "\n") != 1 {
		t.Fatal("old agents require a single newline-delimited line")
	}
	var body struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSuffix(frame, "\n")), &body); err != nil || body.Type == "" {
		t.Fatalf("old agents tolerate JSON-with-type; parse=%v body=%+v", err, body)
	}
	if err := classifyServerLine(frame); err != (Rejection{Reason: "revoked"}) {
		t.Fatalf("classify=%v", err)
	}
}

func TestRevokedDeletesFilesLogsAndStopsRetrying(t *testing.T) {
	pki, err := mtls.GenerateTestPKI()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeFullEnrollment(t, dir, pki)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", pki.ServerTLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var accepts atomic.Int32
	go serveFrames(ln, `{"type":"reject","reason":"revoked"}`+"\n", &accepts)

	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, Config{
			Relay:        ln.Addr().String(),
			CertsDir:     dir,
			EnrollURL:    "http://127.0.0.1:1",
			PingInterval: 40 * time.Millisecond,
		})
	}()

	waitUntil(t, 3*time.Second, func() bool {
		return strings.Contains(logs.String(), RevokedUserMessage)
	})
	if store.LooksEnrolled(dir) {
		t.Fatal("store still looks enrolled after revoke")
	}
	orgDir := store.OrgDir(dir, mtls.TestClientOU)
	if _, err := os.Stat(orgDir); !os.IsNotExist(err) {
		t.Fatal("revoked org dir still present")
	}
	if _, err := os.Stat(sysinfo.StatePath(orgDir)); !os.IsNotExist(err) {
		t.Fatal("system-info.json still present")
	}
	time.Sleep(150 * time.Millisecond)
	if accepts.Load() != 1 {
		t.Fatalf("retries after revoke: accepts=%d", accepts.Load())
	}
	if strings.Contains(logs.String(), "disconnected") {
		t.Fatalf("must not retry: %s", logs.String())
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("dormant cancel: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after ctx cancel while dormant")
	}

	err = Run(context.Background(), Config{
		Relay:     ln.Addr().String(),
		CertsDir:  dir,
		EnrollURL: "http://127.0.0.1:1",
	})
	if err == nil || !strings.Contains(err.Error(), "run `agent enroll` first") {
		t.Fatalf("after delete: %v", err)
	}
}

func TestRenewAllContinuesAfterOneFailure(t *testing.T) {
	pki, err := mtls.GenerateTestPKI()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := writeEnrolled(store.OrgDir(root, "org-ok"), pki); err != nil {
		t.Fatal(err)
	}
	if err := writeEnrolled(store.OrgDir(root, "org-bad"), pki); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteActive(root, "org-ok"); err != nil {
		t.Fatal(err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", pki.ServerTLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var pings atomic.Int32
	gotTwo := make(chan struct{})
	go servePings(ln, &pings, gotTwo)

	var mu sync.Mutex
	seen := map[string]int{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, Config{
			Relay:         ln.Addr().String(),
			CertsDir:      root,
			EnrollURL:     "http://127.0.0.1:1",
			PingInterval:  40 * time.Millisecond,
			RenewInterval: time.Hour,
			Renew: func(enrollURL, certDir string) error {
				mu.Lock()
				seen[filepath.Base(certDir)]++
				mu.Unlock()
				if filepath.Base(certDir) == "org-bad" {
					return fmt.Errorf("forced org-bad failure")
				}
				return nil
			},
		})
	}()

	select {
	case <-gotTwo:
	case err := <-errCh:
		t.Fatalf("connect exited: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out")
	}
	cancel()
	<-errCh
	mu.Lock()
	defer mu.Unlock()
	if seen["org-ok"] < 1 || seen["org-bad"] < 1 {
		t.Fatalf("renew calls=%v; both orgs must be attempted", seen)
	}
}

func TestRevokedRemovesOnlyThatOrgAndClearsActive(t *testing.T) {
	pki, err := mtls.GenerateTestPKI()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := writeEnrolled(store.OrgDir(root, "org-a"), pki); err != nil {
		t.Fatal(err)
	}
	if err := writeEnrolled(store.OrgDir(root, "org-b"), pki); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteActive(root, "org-a"); err != nil {
		t.Fatal(err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", pki.ServerTLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var accepts atomic.Int32
	go serveFrames(ln, `{"type":"reject","reason":"revoked"}`+"\n", &accepts)

	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, Config{
			Relay:        ln.Addr().String(),
			CertsDir:     root,
			EnrollURL:    "http://127.0.0.1:1",
			PingInterval: 40 * time.Millisecond,
		})
	}()

	waitUntil(t, 3*time.Second, func() bool {
		_, err := os.Stat(store.OrgDir(root, "org-a"))
		return os.IsNotExist(err)
	})
	if !strings.Contains(logs.String(), RevokedOrgMessage) {
		t.Fatalf("missing remaining-orgs message:\n%s", logs.String())
	}
	if strings.Contains(logs.String(), RevokedUserMessage) {
		t.Fatalf("must not claim wholly unenrolled:\n%s", logs.String())
	}
	if _, err := store.Load(store.OrgDir(root, "org-b")); err != nil {
		t.Fatalf("other org must survive: %v", err)
	}
	active, err := store.ReadActive(root)
	if err != nil || active != "" {
		t.Fatalf("active should be cleared, got %q err=%v", active, err)
	}
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("dormant cancel: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return")
	}
}

func TestUnknownReasonIsTerminalWithoutDelete(t *testing.T) {
	pki, err := mtls.GenerateTestPKI()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeFullEnrollment(t, dir, pki)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", pki.ServerTLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var accepts atomic.Int32
	go serveFrames(ln, `{"type":"reject","reason":"draining"}`+"\n", &accepts)

	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, Config{
			Relay:        ln.Addr().String(),
			CertsDir:     dir,
			EnrollURL:    "http://127.0.0.1:1",
			PingInterval: 40 * time.Millisecond,
		})
	}()

	waitUntil(t, 3*time.Second, func() bool {
		return strings.Contains(logs.String(), "Credentials were kept")
	})
	if !store.LooksEnrolled(dir) {
		if _, err := store.ResolveActiveDir(dir); err != nil {
			t.Fatalf("unknown reason must keep credentials: %v", err)
		}
	}
	time.Sleep(150 * time.Millisecond)
	if accepts.Load() != 1 {
		t.Fatalf("retries on unknown reason: accepts=%d", accepts.Load())
	}
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("dormant cancel: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
}

func TestUnknownTypeStillRetries(t *testing.T) {
	pki, err := mtls.GenerateTestPKI()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := writeEnrolled(dir, pki); err != nil {
		t.Fatal(err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", pki.ServerTLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var accepts atomic.Int32
	go serveFrames(ln, `{"type":"noop"}`+"\n", &accepts)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, Config{
			Relay:        ln.Addr().String(),
			CertsDir:     dir,
			EnrollURL:    "http://127.0.0.1:1",
			PingInterval: 40 * time.Millisecond,
		})
	}()

	waitUntil(t, 3*time.Second, func() bool { return accepts.Load() >= 2 })
	if !store.LooksEnrolled(dir) {
		t.Fatal("unknown type must not delete")
	}
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("cancel: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func TestDrainRejectAfterFailedWrite(t *testing.T) {
	server, client := net.Pipe()
	go func() {
		_, _ = io.WriteString(server, `{"type":"reject","reason":"revoked"}`+"\n")
		_ = server.Close()
	}()
	reader := bufio.NewReader(client)
	err := drainReject(client, reader, fmt.Errorf("write failed"))
	_ = client.Close()
	if err != (Rejection{Reason: "revoked"}) {
		t.Fatalf("drain=%v", err)
	}
}

func serveFrames(ln net.Listener, frame string, accepts *atomic.Int32) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		accepts.Add(1)
		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			_ = conn.Close()
			continue
		}
		if err := tlsConn.Handshake(); err != nil {
			_ = conn.Close()
			continue
		}
		_, _ = io.WriteString(tlsConn, frame)
		_ = conn.Close()
	}
}

func waitUntil(t *testing.T, d time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out after %s", d)
}

func TestDecideDialSourceRelayWins(t *testing.T) {
	src := DecideDialSource("relay-us-east-01.hookdeploy.dev:9443", "us-west")
	if src.Pin == "" || src.RequestedRegion != "" || !src.RelayWins {
		t.Fatalf("%+v", src)
	}
	auto := DecideDialSource("", "us-east")
	if auto.Pin != "" || auto.RequestedRegion != "us-east" || auto.RelayWins {
		t.Fatalf("%+v", auto)
	}
	neither := DecideDialSource("", "")
	if neither.Pin != "" || neither.RequestedRegion != "" {
		t.Fatalf("%+v", neither)
	}
}

func TestParseConnectFlags(t *testing.T) {
	ok, err := ParseConnectFlags("", "us-west", false, "eu-central,eu-west,eu-central")
	if err != nil {
		t.Fatal(err)
	}
	if ok.RequestedRegion != "us-west" || ok.Enforce || len(ok.Fallback) != 2 {
		t.Fatalf("%+v", ok)
	}
	if ok.Fallback[0] != "eu-central" || ok.Fallback[1] != "eu-west" {
		t.Fatalf("order/dedupe %+v", ok.Fallback)
	}

	_, err = ParseConnectFlags("", "us-west", true, "eu-west")
	if err == nil || !strings.Contains(err.Error(), errEnforceWithFallback) {
		t.Fatalf("enforce+fallback: %v", err)
	}
	_, err = ParseConnectFlags("", "", false, "eu-west")
	if err == nil || !strings.Contains(err.Error(), errFallbackWithoutRegion) {
		t.Fatalf("fallback without region: %v", err)
	}
	_, err = ParseConnectFlags("", "us-west", false, "ap-south")
	if err == nil || !strings.Contains(err.Error(), "ap-south") {
		t.Fatalf("unknown fallback: %v", err)
	}

	pin, err := ParseConnectFlags("relay-us-east-01.hookdeploy.dev", "us-west", true, "eu-west")
	if err != nil {
		t.Fatal(err)
	}
	if pin.Pin == "" || !pin.RelayWins || pin.RequestedRegion != "" || pin.Enforce || len(pin.Fallback) != 0 {
		t.Fatalf("relay must drop placement flags: %+v", pin)
	}
}

func TestFormatAssignmentAndEnforce(t *testing.T) {
	chain := FormatAssignment(&enroll.PlacementResult{
		Hostname:        "relay-us-west-01.hookdeploy.dev",
		RegionKey:       "us-west",
		Reason:          "requested_unavailable",
		RequestedRegion: "us-east",
	})
	if chain != "us-east has no healthy relay; assigned region=us-west hostname=relay-us-west-01.hookdeploy.dev" {
		t.Fatalf("chain: %s", chain)
	}
	explicit := FormatAssignment(&enroll.PlacementResult{
		Hostname:        "relay-eu-central-01.hookdeploy.dev",
		RegionKey:       "eu-central",
		Reason:          "explicit_fallback",
		RequestedRegion: "us-east",
	})
	if explicit != "us-east has no healthy relay; assigned from --fallback region=eu-central hostname=relay-eu-central-01.hookdeploy.dev" {
		t.Fatalf("explicit: %s", explicit)
	}
	direct := FormatAssignment(&enroll.PlacementResult{
		Hostname:  "relay-us-east-01.hookdeploy.dev",
		RegionKey: "us-east",
		Reason:    "requested",
	})
	if direct != "assigned region=us-east hostname=relay-us-east-01.hookdeploy.dev" {
		t.Fatalf("direct: %s", direct)
	}
	if got := FormatEnforcedUnavailable("us-west"); got != "enforced region us-west has no healthy relay (--enforce)" {
		t.Fatalf("enforce: %s", got)
	}
}

func TestRelayPinDoesNotCallPlacement(t *testing.T) {
	pki, err := mtls.GenerateTestPKI()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeFullEnrollment(t, dir, pki)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", pki.ServerTLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var pings atomic.Int32
	gotTwo := make(chan struct{})
	go servePings(ln, &pings, gotTwo)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, Config{
			Relay:           ln.Addr().String(),
			RequestedRegion: "us-west",
			CertsDir:        dir,
			EnrollURL:       "http://127.0.0.1:1",
			PingInterval:    40 * time.Millisecond,
			Place: func(enrollURL, token string, opts enroll.PlacementOptions) (*enroll.PlacementResult, error) {
				t.Error("placement must not run when --relay is set")
				return nil, fmt.Errorf("placement must not run")
			},
		})
	}()
	select {
	case <-gotTwo:
	case err := <-errCh:
		t.Fatalf("connect exited: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out")
	}
	cancel()
	<-errCh
}

func TestNeitherFlagAsksPlacement(t *testing.T) {
	pki, err := mtls.GenerateTestPKI()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeFullEnrollment(t, dir, pki)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", pki.ServerTLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var pings atomic.Int32
	gotTwo := make(chan struct{})
	go servePings(ln, &pings, gotTwo)

	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	var calls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	warning := "Connecting to us-east. This organization is EU-resident. Payloads are not logged or stored on relay nodes, but traffic will transit outside the EU."
	go func() {
		errCh <- Run(ctx, Config{
			CertsDir:     dir,
			EnrollURL:    "http://127.0.0.1:1",
			PingInterval: 40 * time.Millisecond,
			Place: func(enrollURL, token string, opts enroll.PlacementOptions) (*enroll.PlacementResult, error) {
				calls.Add(1)
				if token == "" {
					t.Error("missing token")
				}
				return &enroll.PlacementResult{
					Hostname:  ln.Addr().String(),
					RegionKey: "us-east",
					Warning:   warning,
				}, nil
			},
		})
	}()
	select {
	case <-gotTwo:
	case err := <-errCh:
		t.Fatalf("connect exited: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out")
	}
	if calls.Load() < 1 {
		t.Fatal("placement was not asked")
	}
	out := logs.String()
	if !strings.Contains(out, "assigned region=us-east") {
		t.Fatalf("missing assigned line: %s", out)
	}
	if !strings.Contains(out, warning) {
		t.Fatalf("missing EU warning: %s", out)
	}
	cancel()
	<-errCh
}

func TestPlacementReaskedOnRetry(t *testing.T) {
	pki, err := mtls.GenerateTestPKI()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeFullEnrollment(t, dir, pki)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", pki.ServerTLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var pings atomic.Int32
	gotTwo := make(chan struct{})
	go servePings(ln, &pings, gotTwo)

	var calls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, Config{
			RequestedRegion: "us-east",
			CertsDir:        dir,
			EnrollURL:       "http://127.0.0.1:1",
			PingInterval:    40 * time.Millisecond,
			Place: func(enrollURL, token string, opts enroll.PlacementOptions) (*enroll.PlacementResult, error) {
				n := calls.Add(1)
				if opts.Region != "us-east" {
					t.Errorf("region=%q", opts.Region)
				}
				if n == 1 {
					return &enroll.PlacementResult{Hostname: "127.0.0.1:1", RegionKey: "us-east"}, nil
				}
				return &enroll.PlacementResult{Hostname: ln.Addr().String(), RegionKey: "us-west"}, nil
			},
		})
	}()
	select {
	case <-gotTwo:
	case err := <-errCh:
		t.Fatalf("connect exited: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for retry placement")
	}
	if calls.Load() < 2 {
		t.Fatalf("place calls=%d want >= 2", calls.Load())
	}
	cancel()
	<-errCh
}

func TestPlacementFailureBacksOffWithoutCrashing(t *testing.T) {
	pki, err := mtls.GenerateTestPKI()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeFullEnrollment(t, dir, pki)

	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	var calls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, Config{
			CertsDir:     dir,
			EnrollURL:    "http://127.0.0.1:1",
			PingInterval: 40 * time.Millisecond,
			Place: func(enrollURL, token string, opts enroll.PlacementOptions) (*enroll.PlacementResult, error) {
				calls.Add(1)
				return nil, fmt.Errorf("no healthy relay is available")
			},
		})
	}()
	waitUntil(t, 4*time.Second, func() bool {
		return calls.Load() >= 2 && strings.Contains(logs.String(), "placement failed: no healthy relay is available")
	})
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func TestEnforcedUnavailableBacksOffWithoutExiting(t *testing.T) {
	pki, err := mtls.GenerateTestPKI()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeFullEnrollment(t, dir, pki)

	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	var calls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, Config{
			RequestedRegion: "us-west",
			Enforce:         true,
			CertsDir:        dir,
			EnrollURL:       "http://127.0.0.1:1",
			PingInterval:    40 * time.Millisecond,
			Place: func(enrollURL, token string, opts enroll.PlacementOptions) (*enroll.PlacementResult, error) {
				calls.Add(1)
				if !opts.Enforce || opts.Region != "us-west" {
					t.Errorf("opts=%+v", opts)
				}
				return nil, &enroll.APIError{Status: 503, Code: "enforced_region_unavailable", Message: "enforced region us-west has no healthy relay"}
			},
		})
	}()
	want := "placement failed: enforced region us-west has no healthy relay (--enforce)"
	waitUntil(t, 4*time.Second, func() bool {
		return calls.Load() >= 2 && strings.Contains(logs.String(), want)
	})
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}
