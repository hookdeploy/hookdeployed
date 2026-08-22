package connect

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/hookdeploy/hookdeployed/internal/enroll"
	"github.com/hookdeploy/hookdeployed/internal/store"
	"github.com/hookdeploy/hookdeployed/internal/sysinfo"
)

const (
	DefaultPort         = "9443"
	DefaultPingInterval = 10 * time.Second
	// DefaultRenewInterval is how often a live connection re-runs MaybeRenew.
	// Halfway of a 24h leaf is ~12h; 5m is frequent enough for a client without
	// the 1m cadence the relay uses as infrastructure. Wake detection uses the
	// ping ticker (10s), so suspend is noticed well before this fires.
	DefaultRenewInterval = 5 * time.Minute
	maxBackoff           = 30 * time.Second
	minBackoff           = time.Second
	// drainRejectDeadline is how long pingOnce waits for a reject frame
	// after a PING write fails (the relay may have written then closed).
	drainRejectDeadline = 200 * time.Millisecond
)

// RevokedUserMessage is the jargon-free line logged on reason=revoked.
const RevokedUserMessage = "this agent was revoked and can no longer connect. Local credentials were removed. Run `agent enroll`, then `agent connect`."

// Rejection is a terminal server→agent frame. Reason "revoked" deletes
// credentials; any other reason stops retry without deleting.
type Rejection struct {
	Reason string
}

func (e Rejection) Error() string {
	if e.Reason == "" {
		return "rejected"
	}
	return "rejected: " + e.Reason
}

type Config struct {
	Relay         string
	CertsDir      string
	EnrollURL     string
	PingInterval  time.Duration
	RenewInterval time.Duration
	// Renew overrides enroll.MaybeRenew (tests). Nil uses the real function.
	Renew func(enrollURL, certDir string) error
	// Report overrides sysinfo.MaybeReport (tests). Nil uses the real function.
	Report func(enrollURL, certDir string) error
}

func ParseRelay(relay string) (host, addr string, err error) {
	if relay == "" {
		return "", "", fmt.Errorf("--relay is required")
	}
	if h, p, splitErr := net.SplitHostPort(relay); splitErr == nil {
		if h == "" {
			return "", "", fmt.Errorf("--relay host is empty")
		}
		return h, net.JoinHostPort(h, p), nil
	}
	return relay, net.JoinHostPort(relay, DefaultPort), nil
}

func NextBackoff(prev time.Duration) time.Duration {
	if prev < minBackoff {
		return minBackoff
	}
	next := prev * 2
	if next > maxBackoff {
		return maxBackoff
	}
	return next
}

// IsWakeEvent reports a wall-clock gap much larger than sampleInterval,
// which typically means the process was suspended. Monotonic readings are
// stripped with Round(0): time.Since uses the monotonic clock and does not
// advance during OS sleep on Windows, macOS, and Linux.
func IsWakeEvent(last, now time.Time, sampleInterval time.Duration) bool {
	if sampleInterval <= 0 || last.IsZero() {
		return false
	}
	gap := now.Round(0).Sub(last.Round(0))
	return gap > 2*sampleInterval
}

func attemptRenew(cfg Config) {
	fn := cfg.Renew
	if fn == nil {
		fn = enroll.MaybeRenew
	}
	if err := fn(cfg.EnrollURL, cfg.CertsDir); err != nil {
		log.Printf("renew skipped/failed: %v", err)
	}
}

func attemptReport(cfg Config) {
	fn := cfg.Report
	if fn == nil {
		fn = sysinfo.MaybeReport
	}
	if err := fn(cfg.EnrollURL, cfg.CertsDir); err != nil {
		// Non-fatal. Do not log cfg contents — the token lives in the cert dir.
		log.Printf("system-info report failed: %v", err)
	}
}

func Run(ctx context.Context, cfg Config) error {
	if cfg.PingInterval <= 0 {
		cfg.PingInterval = DefaultPingInterval
	}
	if cfg.RenewInterval <= 0 {
		cfg.RenewInterval = DefaultRenewInterval
	}
	host, addr, err := ParseRelay(cfg.Relay)
	if err != nil {
		return err
	}

	if _, err := store.Load(cfg.CertsDir); err != nil {
		return fmt.Errorf("no enrolled cert in %s — run `agent enroll` first", cfg.CertsDir)
	}

	backoff := time.Duration(0)
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		// Report before renew so the presented token is the one still on
		// disk. A 401 from a just-rotated token is non-fatal; the next
		// connect retries after this iteration's MaybeRenew writes the new
		// token. Do not add a rotation grace window.
		attemptReport(cfg)
		attemptRenew(cfg)
		if err := dialAndHeartbeat(ctx, cfg, host, addr); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var rej Rejection
			if errors.As(err, &rej) {
				return settleRejection(ctx, cfg, rej)
			}
			backoff = NextBackoff(backoff)
			log.Printf("disconnected relay=%s; retry in %s", host, backoff)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff):
			}
			continue
		}
		return nil
	}
}

func dialAndHeartbeat(ctx context.Context, cfg Config, host, addr string) error {
	material, err := store.Load(cfg.CertsDir)
	if err != nil {
		return fmt.Errorf("reload certs: %w", err)
	}
	tlsCfg, err := material.ClientTLSConfigFor(host)
	if err != nil {
		return err
	}

	dialer := &tls.Dialer{Config: tlsCfg}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		log.Printf("dial relay=%s: %v", host, err)
		return err
	}
	defer conn.Close()
	log.Printf("connected relay=%s remote=%s", host, conn.RemoteAddr())

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	defer close(done)

	reader := bufio.NewReader(conn)
	if err := pingOnce(conn, reader, cfg.PingInterval); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if _, ok := err.(Rejection); !ok {
			log.Printf("heartbeat dropped relay=%s", host)
		}
		return err
	}

	pingTicker := time.NewTicker(cfg.PingInterval)
	defer pingTicker.Stop()
	renewTicker := time.NewTicker(cfg.RenewInterval)
	defer renewTicker.Stop()
	lastWall := time.Now()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-pingTicker.C:
			now := time.Now()
			if IsWakeEvent(lastWall, now, cfg.PingInterval) {
				attemptRenew(cfg)
			}
			lastWall = now
			if err := pingOnce(conn, reader, cfg.PingInterval); err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if _, ok := err.(Rejection); !ok {
					log.Printf("heartbeat dropped relay=%s", host)
				}
				return err
			}
		case <-renewTicker.C:
			lastWall = time.Now()
			attemptRenew(cfg)
		}
	}
}

func pingOnce(conn net.Conn, reader *bufio.Reader, interval time.Duration) error {
	if _, err := io.WriteString(conn, "PING\n"); err != nil {
		return drainReject(conn, reader, err)
	}
	slack := 2 * time.Second
	if interval > slack {
		slack = interval
	}
	_ = conn.SetReadDeadline(time.Now().Add(interval + slack))
	line, err := reader.ReadString('\n')
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return err
	}
	return classifyServerLine(line)
}

func drainReject(conn net.Conn, reader *bufio.Reader, writeErr error) error {
	_ = conn.SetReadDeadline(time.Now().Add(drainRejectDeadline))
	line, err := reader.ReadString('\n')
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return writeErr
	}
	if classified := classifyServerLine(line); errors.As(classified, &Rejection{}) {
		return classified
	}
	return writeErr
}

func classifyServerLine(line string) error {
	trimmed := trimHeartbeat(line)
	// INVARIANT: never log the line, its length, or a hash.
	if trimmed == "PONG" {
		return nil
	}
	if reason, ok := parseReject(trimmed); ok {
		return Rejection{Reason: reason}
	}
	return fmt.Errorf("heartbeat: expected PONG")
}

func parseReject(line string) (reason string, ok bool) {
	var body struct {
		Type   string `json:"type"`
		Reason string `json:"reason"`
	}
	if json.Unmarshal([]byte(line), &body) != nil {
		return "", false
	}
	if body.Type != "reject" {
		return "", false
	}
	return body.Reason, true
}

func settleRejection(ctx context.Context, cfg Config, rej Rejection) error {
	if rej.Reason == "revoked" {
		log.Print(RevokedUserMessage)
		if err := store.ClearEnrollment(cfg.CertsDir); err != nil {
			log.Printf("could not finish removing credentials: %v", err)
		}
		if err := sysinfo.ClearState(cfg.CertsDir); err != nil {
			log.Printf("could not clear system-info state: %v", err)
		}
	} else {
		log.Printf("this connection was ended (%s). Not retrying. Credentials were kept.", rej.Reason)
	}
	<-ctx.Done()
	return nil
}

func trimHeartbeat(line string) string {
	for len(line) > 0 && (line[len(line)-1] == '\n' || line[len(line)-1] == '\r') {
		line = line[:len(line)-1]
	}
	return line
}
