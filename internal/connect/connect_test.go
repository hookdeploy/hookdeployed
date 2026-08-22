package connect

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hookdeploy/hookdeployed/internal/enroll"
	"github.com/hookdeploy/hookdeployed/internal/mtls"
	"github.com/hookdeploy/hookdeployed/internal/store"
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
