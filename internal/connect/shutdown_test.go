package connect

import (
	"context"
	"crypto/tls"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hookdeploy/hookdeployed/internal/mtls"
)

// shutdownLatencyBudget is how long connect.Run may take to return after ctx
// cancel during an active session. The tray's shutdown_for_update calls
// stop_connect (kill, no dedicated wait) then sidecar_snapshot; connect is
// cleared from tray state immediately on kill, but the OS must release the
// hookdeployed.exe file lock when the process exits. TAP_STOP_TIMEOUT is 8s
// and strict tap teardown uses wait_child_exited(2s); connect has no analogous
// wait — this budget is the CLI-side guarantee that graceful teardown (SIGTERM
// → ctx cancel) finishes well inside those windows.
const shutdownLatencyBudget = time.Second

func startConnectedRun(t *testing.T, ln net.Listener, dir string) (context.Context, context.CancelFunc, chan error) {
	t.Helper()
	var pings atomic.Int32
	gotTwo := make(chan struct{})
	go servePings(ln, &pings, gotTwo)

	ctx, cancel := context.WithCancel(context.Background())
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
		t.Fatalf("connect exited before steady state: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for steady state; pings=%d", pings.Load())
	}
	return ctx, cancel, errCh
}

func TestRunReturnsPromptlyOnCancelDuringActiveSession(t *testing.T) {
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

	_, cancel, errCh := startConnectedRun(t, ln, dir)

	cancelAt := time.Now()
	cancel()
	select {
	case err := <-errCh:
		elapsed := time.Since(cancelAt)
		if err != nil {
			t.Fatalf("shutdown returned error: %v", err)
		}
		if elapsed > shutdownLatencyBudget {
			t.Fatalf("Run took %s to return after cancel, want <%s", elapsed, shutdownLatencyBudget)
		}
		t.Logf("shutdown latency after cancel: %s", elapsed)
	case <-time.After(shutdownLatencyBudget):
		t.Fatalf("Run did not return within %s after cancel", shutdownLatencyBudget)
	}
}

func TestRunCanRestartImmediatelyAfterCancel(t *testing.T) {
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

	_, cancel, errCh := startConnectedRun(t, ln, dir)
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("first Run shutdown: %v", err)
		}
	case <-time.After(shutdownLatencyBudget):
		t.Fatal("first Run did not exit after cancel")
	}

	// Re-spawn proxy: a second Run must reach steady state immediately, with
	// no contention from the prior session (would fail if cleanup blocked or
	// a stale handle prevented a new dial).
	restartAt := time.Now()
	_, cancel2, errCh2 := startConnectedRun(t, ln, dir)
	defer cancel2()
	elapsed := time.Since(restartAt)
	if elapsed > 3*time.Second {
		t.Fatalf("second Run took %s to reach steady state, want immediate re-dial", elapsed)
	}
	t.Logf("re-spawn to steady state: %s", elapsed)

	cancel2()
	select {
	case err := <-errCh2:
		if err != nil {
			t.Fatalf("second Run shutdown: %v", err)
		}
	case <-time.After(shutdownLatencyBudget):
		t.Fatal("second Run did not exit after cancel")
	}
}
