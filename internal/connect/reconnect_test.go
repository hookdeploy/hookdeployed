package connect

import (
	"bytes"
	"context"
	"crypto/tls"
	"log"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hookdeploy/hookdeployed/internal/mtls"
)

func TestHealthySessionThenEndRetriesImmediately(t *testing.T) {
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

	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	secondGap := make(chan time.Duration, 1)
	go func() {
		cc, conn, err := acceptH2Client(ln)
		if err != nil {
			return
		}
		time.Sleep(minHealthySession + 150*time.Millisecond)
		closedAt := time.Now()
		_ = cc.Close()
		_ = conn.Close()
		cc2, conn2, err := acceptH2Client(ln)
		if err != nil {
			return
		}
		secondGap <- time.Since(closedAt)
		_ = cc2.Close()
		_ = conn2.Close()
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, Config{
			Relay:         ln.Addr().String(),
			CertsDir:      dir,
			EnrollURL:     "http://127.0.0.1:1",
			PingInterval:  time.Hour,
			RenewInterval: time.Hour,
		})
	}()

	select {
	case gap := <-secondGap:
		if gap > 400*time.Millisecond {
			t.Fatalf("healthy session end should redial immediately, gap=%s logs:\n%s", gap, logs.String())
		}
	case err := <-errCh:
		t.Fatalf("Run exited: %v\n%s", err, logs.String())
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out\n%s", logs.String())
	}
	if strings.Contains(logs.String(), "retry in") {
		t.Fatalf("healthy session end must not use failure backoff:\n%s", logs.String())
	}
	if !strings.Contains(logs.String(), "reconnecting") {
		t.Fatalf("expected reconnecting log:\n%s", logs.String())
	}
	cancel()
	<-errCh
}

func TestDialFailsTwiceEscalatesBackoff(t *testing.T) {
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
	addr := ln.Addr().String()
	_ = ln.Close()

	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, Config{
			Relay:         addr,
			CertsDir:      dir,
			EnrollURL:     "http://127.0.0.1:1",
			PingInterval:  time.Hour,
			RenewInterval: time.Hour,
		})
	}()

	waitUntil(t, 2*time.Second, func() bool {
		return strings.Contains(logs.String(), "retry in 1s")
	})
	waitUntil(t, 3*time.Second, func() bool {
		return strings.Contains(logs.String(), "retry in 2s")
	})
	if strings.Contains(logs.String(), "reconnecting") {
		t.Fatalf("dial failures must not take the session-end immediate path:\n%s", logs.String())
	}
	cancel()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func TestShortSessionGetsOneImmediateRetryThenBackoff(t *testing.T) {
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

	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	type accept struct {
		at time.Time
	}
	got := make(chan accept, 3)
	go func() {
		for i := 0; i < 3; i++ {
			cc, conn, err := acceptH2Client(ln)
			if err != nil {
				return
			}
			got <- accept{at: time.Now()}
			_ = cc.Close()
			_ = conn.Close()
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, Config{
			Relay:         ln.Addr().String(),
			CertsDir:      dir,
			EnrollURL:     "http://127.0.0.1:1",
			PingInterval:  time.Hour,
			RenewInterval: time.Hour,
		})
	}()

	var times [3]time.Time
	for i := 0; i < 3; i++ {
		select {
		case a := <-got:
			times[i] = a.at
		case err := <-errCh:
			t.Fatalf("Run exited at accept %d: %v\n%s", i, err, logs.String())
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for accept %d\n%s", i, logs.String())
		}
	}
	firstGap := times[1].Sub(times[0])
	secondGap := times[2].Sub(times[1])
	if firstGap > 400*time.Millisecond {
		t.Fatalf("first short-session retry should be immediate, gap=%s\n%s", firstGap, logs.String())
	}
	if secondGap < 900*time.Millisecond {
		t.Fatalf("second short-session retry should pay minBackoff, gap=%s\n%s", secondGap, logs.String())
	}
	if !strings.Contains(logs.String(), "reconnecting") {
		t.Fatalf("first short end should reconnect immediately:\n%s", logs.String())
	}
	if !strings.Contains(logs.String(), "retry in 1s") {
		t.Fatalf("second short end should escalate:\n%s", logs.String())
	}
	cancel()
	<-errCh
}

func TestDrainingStillUsesBackoffNotImmediateRetry(t *testing.T) {
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

	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	var accepts atomic.Int32
	first := make(chan time.Time, 1)
	second := make(chan time.Time, 1)
	go func() {
		for {
			cc, conn, err := acceptH2Client(ln)
			if err != nil {
				return
			}
			n := accepts.Add(1)
			now := time.Now()
			if n == 1 {
				first <- now
			} else if n == 2 {
				second <- now
			}
			_ = sendTestControl(cc, "draining")
			_ = cc.Close()
			_ = conn.Close()
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, Config{
			Relay:         ln.Addr().String(),
			CertsDir:      dir,
			EnrollURL:     "http://127.0.0.1:1",
			PingInterval:  time.Hour,
			RenewInterval: time.Hour,
		})
	}()

	var t0, t1 time.Time
	select {
	case t0 = <-first:
	case <-time.After(3 * time.Second):
		t.Fatal("no first drain accept")
	}
	select {
	case t1 = <-second:
	case <-time.After(3 * time.Second):
		t.Fatalf("no second drain accept\n%s", logs.String())
	}
	gap := t1.Sub(t0)
	if gap < 900*time.Millisecond {
		t.Fatalf("draining must keep failure backoff, gap=%s\n%s", gap, logs.String())
	}
	if strings.Contains(logs.String(), "reconnecting") {
		t.Fatalf("draining must not take the session-end immediate path:\n%s", logs.String())
	}
	if !strings.Contains(logs.String(), DrainingUserMessage) {
		t.Fatalf("missing draining message:\n%s", logs.String())
	}
	cancel()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return")
	}
}

func TestRevokedDoesNotTakeImmediateRetryPath(t *testing.T) {
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
	go serveControl(ln, "revoked", &accepts)

	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

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
		})
	}()

	waitUntil(t, 3*time.Second, func() bool {
		return strings.Contains(logs.String(), RevokedUserMessage)
	})
	time.Sleep(150 * time.Millisecond)
	if accepts.Load() != 1 {
		t.Fatalf("revoked retried: accepts=%d", accepts.Load())
	}
	if strings.Contains(logs.String(), "reconnecting") {
		t.Fatalf("revoked must not take the session-end immediate path:\n%s", logs.String())
	}
	cancel()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return")
	}
}

func TestRenewLoopContextCancelledWhenSessionEnds(t *testing.T) {
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

	started := make(chan context.Context, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, Config{
			Relay:         ln.Addr().String(),
			CertsDir:      dir,
			EnrollURL:     "http://127.0.0.1:1",
			PingInterval:  time.Hour,
			RenewInterval: time.Hour,
			RenewLoopStarted: func(sessCtx context.Context) {
				started <- sessCtx
			},
		})
	}()

	cc, conn, err := acceptH2Client(ln)
	if err != nil {
		t.Fatal(err)
	}
	var sessCtx context.Context
	select {
	case sessCtx = <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("renewLoop did not start")
	}
	_ = cc.Close()
	_ = conn.Close()
	_ = ln.Close()

	select {
	case <-sessCtx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("session renewLoop context was not cancelled after the session ended")
	}
	cancel()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return")
	}
}
