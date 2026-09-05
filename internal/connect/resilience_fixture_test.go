package connect

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hookdeploy/hookdeployed/internal/enroll"
	"github.com/hookdeploy/hookdeployed/internal/mtls"
	"github.com/hookdeploy/hookdeployed/internal/store"
)

// Dead renewal on placement must terminate (B2), not retry forever.
func TestUnauthorizedPlacementRetriesWithBackoffCeiling(t *testing.T) {
	pki, err := mtls.GenerateTestPKI()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeFullEnrollment(t, dir, pki)

	var calls atomic.Int32
	var logs strings.Builder
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, Config{
			CertsDir:      dir,
			EnrollURL:     "http://127.0.0.1:1",
			PingInterval:  time.Hour,
			RenewInterval: time.Hour,
			// Renew succeeds / no-op so placement is the auth-death path.
			Renew: func(enrollURL, certDir string) error { return nil },
			Place: func(enrollURL, token string, opts enroll.PlacementOptions) (*enroll.PlacementResult, error) {
				calls.Add(1)
				return nil, &enroll.APIError{
					Status:  401,
					Code:    "unauthorized",
					Message: "renewal token expired",
				}
			},
		})
	}()

	waitUntil(t, 3*time.Second, func() bool {
		return strings.Contains(logs.String(), DeadCredentialUserMessage)
	})
	if calls.Load() != 1 {
		t.Fatalf("calls=%d want exactly 1 (terminal; no placement retry)", calls.Load())
	}
	out := logs.String()
	if strings.Contains(out, "retry in") || strings.Contains(out, "reconnecting") {
		t.Fatalf("dead credential must not backoff-retry:\n%s", out)
	}
	if store.LooksEnrolled(dir) {
		t.Fatal("credentials should be removed after dead renewal")
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
}

func TestDeadRenewOnActiveOrgTerminatesWithoutPlacement(t *testing.T) {
	pki, err := mtls.GenerateTestPKI()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeFullEnrollment(t, dir, pki)

	var places atomic.Int32
	var logs strings.Builder
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, Config{
			CertsDir:      dir,
			EnrollURL:     "http://127.0.0.1:1",
			PingInterval:  time.Hour,
			RenewInterval: time.Hour,
			Renew: func(enrollURL, certDir string) error {
				return &enroll.APIError{Status: 401, Code: "unauthorized", Message: "renewal token revoked"}
			},
			Place: func(enrollURL, token string, opts enroll.PlacementOptions) (*enroll.PlacementResult, error) {
				places.Add(1)
				return nil, fmt.Errorf("placement must not run")
			},
		})
	}()

	waitUntil(t, 3*time.Second, func() bool {
		return strings.Contains(logs.String(), DeadCredentialUserMessage)
	})
	if places.Load() != 0 {
		t.Fatalf("placement calls=%d want 0", places.Load())
	}
	cancel()
	<-errCh
}

func TestTransientPlacementStillRetries(t *testing.T) {
	pki, err := mtls.GenerateTestPKI()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeFullEnrollment(t, dir, pki)

	var calls atomic.Int32
	var logs strings.Builder
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, Config{
			CertsDir:      dir,
			EnrollURL:     "http://127.0.0.1:1",
			PingInterval:  time.Hour,
			RenewInterval: time.Hour,
			Renew:         func(string, string) error { return nil },
			Place: func(enrollURL, token string, opts enroll.PlacementOptions) (*enroll.PlacementResult, error) {
				n := calls.Add(1)
				if n >= 2 {
					cancel()
				}
				return nil, fmt.Errorf("no healthy relay is available")
			},
		})
	}()

	waitUntil(t, 4*time.Second, func() bool {
		return calls.Load() >= 2 && strings.Contains(logs.String(), "placement failed:")
	})
	if strings.Contains(logs.String(), DeadCredentialUserMessage) {
		t.Fatalf("transient placement must not settle as dead credential:\n%s", logs.String())
	}
	cancel()
	<-errCh
}

func TestNextBackoffCapsAtThirtySeconds(t *testing.T) {
	got := NextBackoff(0)
	if got != time.Second {
		t.Fatalf("from 0 got %s", got)
	}
	got = NextBackoff(time.Second)
	if got != 2*time.Second {
		t.Fatalf("from 1s got %s", got)
	}
	got = NextBackoff(16 * time.Second)
	if got != 30*time.Second {
		t.Fatalf("from 16s got %s want 30s cap", got)
	}
	got = NextBackoff(30 * time.Second)
	if got != 30*time.Second {
		t.Fatalf("at cap got %s", got)
	}
}

func TestDialCertValidityWithSkewIsTerminal(t *testing.T) {
	enroll.ResetObservedClockSkew()
	defer enroll.ResetObservedClockSkew()
	enroll.SetObservedClockSkewForTest(10 * time.Minute)

	pki, err := mtls.GenerateTestPKI()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeFullEnrollment(t, dir, pki)

	var logs strings.Builder
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, Config{
			Relay:         "127.0.0.1:1",
			CertsDir:      dir,
			EnrollURL:     "http://127.0.0.1:1",
			PingInterval:  time.Hour,
			RenewInterval: time.Hour,
			Renew:         func(string, string) error { return nil },
		})
	}()

	// Without a real TLS cert-time error, dial to :1 is connection refused —
	// that must keep retrying (not clock-skew terminal). Cancel after one retry log.
	waitUntil(t, 3*time.Second, func() bool {
		return strings.Contains(logs.String(), "retry in")
	})
	if strings.Contains(logs.String(), ClockSkewUserMessage) {
		t.Fatalf("connection refused must not become clock skew:\n%s", logs.String())
	}
	cancel()
	<-errCh
}

func TestSettleClockSkewKeepsCredentials(t *testing.T) {
	enroll.ResetObservedClockSkew()
	defer enroll.ResetObservedClockSkew()

	pki, err := mtls.GenerateTestPKI()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeFullEnrollment(t, dir, pki)

	var logs strings.Builder
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, Config{
			CertsDir:      dir,
			EnrollURL:     "http://127.0.0.1:1",
			PingInterval:  time.Hour,
			RenewInterval: time.Hour,
			Renew: func(string, string) error {
				enroll.SetObservedClockSkewForTest(-12 * time.Minute)
				return fmt.Errorf("certificate not yet valid")
			},
			Place: func(string, string, enroll.PlacementOptions) (*enroll.PlacementResult, error) {
				t.Fatal("placement must not run after clock-skew renew")
				return nil, nil
			},
		})
	}()

	waitUntil(t, 3*time.Second, func() bool {
		return strings.Contains(logs.String(), ClockSkewUserMessage)
	})
	if !store.LooksEnrolled(dir) {
		t.Fatal("clock skew must keep local credentials")
	}
	if strings.Contains(logs.String(), DeadCredentialUserMessage) {
		t.Fatal("clock skew must not look like dead credential")
	}
	cancel()
	<-errCh
}
