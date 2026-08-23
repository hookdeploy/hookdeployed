package connect

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/hookdeploy/hookdeployed/internal/enroll"
	"github.com/hookdeploy/hookdeployed/internal/store"
	"github.com/hookdeploy/hookdeployed/internal/sysinfo"
	"golang.org/x/net/http2"
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

	// LocalDeliverURL is the hardcoded local-service target for this pass.
	// Next pass makes this configurable.
	LocalDeliverURL = "http://127.0.0.1:9999"
	// ControlPath is reserved. The relay POSTs revoke/drain here.
	// It is never forwarded to the local service.
	ControlPath = "/v1/control"
	// localDeliverTimeout bounds the hop to the agent's machine, not the relay session.
	localDeliverTimeout = 30 * time.Second
)

// RevokedUserMessage is the jargon-free line logged on reason=revoked
// when no other orgs remain enrolled.
const RevokedUserMessage = "this agent was revoked and can no longer connect. Local credentials were removed. Run `agent enroll`, then `agent connect`."

// RevokedOrgMessage is logged when the revoked org was one of several.
const RevokedOrgMessage = "this organization's credentials were removed. Other organizations are still enrolled. Run `agent switch` to pick one, or `agent enroll` to re-enroll this org."

// DrainingUserMessage is logged when the relay is taking this box out of
// rotation. Credentials stay; the next loop iteration re-places.
const DrainingUserMessage = "this relay is draining. Moving you to another relay. Credentials were kept."

// Rejection is a server→agent frame. Reason "revoked" deletes credentials
// and stops. Reason "draining" re-places without deleting. Any other
// reason stops retry without deleting.
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
	Relay           string
	RequestedRegion string
	Enforce         bool
	Fallback        []string
	CertsDir        string
	EnrollURL       string
	PingInterval    time.Duration
	RenewInterval   time.Duration
	// Renew overrides enroll.MaybeRenew (tests). Nil uses the real function.
	Renew func(enrollURL, certDir string) error
	// Report overrides sysinfo.MaybeReport (tests). Nil uses the real function.
	Report func(enrollURL, certDir string) error
	// Place overrides enrollment placement (tests). Nil uses enroll.Client.Placement.
	Place func(enrollURL, token string, opts enroll.PlacementOptions) (*enroll.PlacementResult, error)
	// LocalURL overrides LocalDeliverURL (tests). Empty uses the constant.
	LocalURL string
}

// DialSource is how connect decides pin vs placement.
type DialSource struct {
	Pin             string
	RequestedRegion string
	Enforce         bool
	Fallback        []string
	RelayWins       bool
}

// RelayPinPrecedenceMessage is logged when --relay is set with any placement flags.
const RelayPinPrecedenceMessage = "--relay pins this instance; --region, --enforce, and --fallback are ignored"

const (
	errEnforceWithFallback   = "--enforce and --fallback cannot be used together"
	errFallbackWithoutRegion = "--fallback requires --region"
)

var knownRelayRegions = map[string]struct{}{
	"us-west": {}, "us-east": {}, "uk-london": {},
	"eu-west": {}, "eu-central": {}, "ap-southeast": {}, "au-southeast": {},
}

// ParseConnectFlags: --relay wins over --region / --enforce / --fallback.
// --enforce + --fallback is an error. --fallback without --region is an error.
func ParseConnectFlags(relay, region string, enforce bool, fallbackRaw string) (DialSource, error) {
	if relay != "" {
		ignored := region != "" || enforce || strings.TrimSpace(fallbackRaw) != ""
		return DialSource{Pin: relay, RelayWins: ignored}, nil
	}
	fallback, err := parseFallbackList(fallbackRaw)
	if err != nil {
		return DialSource{}, err
	}
	if enforce && len(fallback) > 0 {
		return DialSource{}, fmt.Errorf("%s", errEnforceWithFallback)
	}
	if len(fallback) > 0 && region == "" {
		return DialSource{}, fmt.Errorf("%s", errFallbackWithoutRegion)
	}
	if region != "" {
		if _, ok := knownRelayRegions[region]; !ok {
			return DialSource{}, fmt.Errorf("--region %q is not a known relay region", region)
		}
	}
	if enforce && region == "" {
		return DialSource{}, fmt.Errorf("--enforce requires --region")
	}
	return DialSource{RequestedRegion: region, Enforce: enforce, Fallback: fallback}, nil
}

func parseFallbackList(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	seen := map[string]struct{}{}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		region := strings.TrimSpace(part)
		if region == "" {
			continue
		}
		if _, ok := knownRelayRegions[region]; !ok {
			return nil, fmt.Errorf("--fallback region %q is not a known relay region", region)
		}
		if _, dup := seen[region]; dup {
			continue
		}
		seen[region] = struct{}{}
		out = append(out, region)
	}
	return out, nil
}

// DecideDialSource: --relay wins and ignores --region; neither means auto-place.
func DecideDialSource(relay, region string) DialSource {
	src, err := ParseConnectFlags(relay, region, false, "")
	if err != nil {
		return DialSource{RequestedRegion: region}
	}
	return src
}

// FormatAssignment is the connect log line after a successful placement.
func FormatAssignment(result *enroll.PlacementResult) string {
	requested := strings.TrimSpace(result.RequestedRegion)
	if requested != "" && requested != result.RegionKey {
		switch result.Reason {
		case "explicit_fallback":
			return fmt.Sprintf(
				"%s has no healthy relay; assigned from --fallback region=%s hostname=%s",
				requested, result.RegionKey, result.Hostname,
			)
		case "requested_unavailable":
			return fmt.Sprintf(
				"%s has no healthy relay; assigned region=%s hostname=%s",
				requested, result.RegionKey, result.Hostname,
			)
		}
	}
	return fmt.Sprintf("assigned region=%s hostname=%s", result.RegionKey, result.Hostname)
}

func FormatEnforcedUnavailable(region string) string {
	if strings.TrimSpace(region) == "" {
		region = "the requested region"
	}
	return fmt.Sprintf("enforced region %s has no healthy relay (--enforce)", region)
}

func resolveDial(cfg Config) (host, addr string, err error) {
	if cfg.Relay != "" {
		return ParseRelay(cfg.Relay)
	}
	placed, err := fetchPlacement(cfg)
	if err != nil {
		return "", "", err
	}
	return ParseRelay(placed.Hostname)
}

func fetchPlacement(cfg Config) (*enroll.PlacementResult, error) {
	orgDir, err := store.ResolveActiveDir(cfg.CertsDir)
	if err != nil {
		return nil, store.ExplainResolve(cfg.CertsDir, err)
	}
	material, err := store.Load(orgDir)
	if err != nil {
		return nil, fmt.Errorf("load certs: %w", err)
	}
	token := strings.TrimSpace(material.RenewalToken)
	if token == "" {
		return nil, fmt.Errorf("no renewal token — run `agent enroll` or pass --relay")
	}
	fn := cfg.Place
	if fn == nil {
		client := &enroll.Client{
			BaseURL:    strings.TrimRight(cfg.EnrollURL, "/"),
			HTTPClient: &http.Client{Timeout: 10 * time.Second},
		}
		fn = func(enrollURL, renewalToken string, opts enroll.PlacementOptions) (*enroll.PlacementResult, error) {
			_ = enrollURL
			return client.Placement(renewalToken, opts)
		}
	}
	result, err := fn(cfg.EnrollURL, token, enroll.PlacementOptions{
		Region:   cfg.RequestedRegion,
		Enforce:  cfg.Enforce,
		Fallback: cfg.Fallback,
	})
	if err != nil {
		if enroll.IsEnforcedUnavailable(err) {
			return nil, fmt.Errorf("%s", FormatEnforcedUnavailable(cfg.RequestedRegion))
		}
		return nil, err
	}
	log.Print(FormatAssignment(result))
	if result.Warning != "" {
		log.Print(result.Warning)
	}
	return result, nil
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
	dirs, err := store.ListOrgDirs(cfg.CertsDir)
	if err != nil {
		log.Printf("renew skipped/failed: %v", err)
		return
	}
	if len(dirs) == 0 {
		if err := fn(cfg.EnrollURL, cfg.CertsDir); err != nil {
			log.Printf("renew skipped/failed: %v", err)
		}
		return
	}
	for _, dir := range dirs {
		if err := fn(cfg.EnrollURL, dir); err != nil {
			log.Printf("renew skipped/failed org=%s: %v", filepath.Base(dir), err)
		}
	}
}

func attemptReport(cfg Config) {
	fn := cfg.Report
	if fn == nil {
		fn = sysinfo.MaybeReport
	}
	dir, err := store.ResolveActiveDir(cfg.CertsDir)
	if err != nil {
		return
	}
	if err := fn(cfg.EnrollURL, dir); err != nil {
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
	if _, err := store.ResolveActiveDir(cfg.CertsDir); err != nil {
		return store.ExplainResolve(cfg.CertsDir, err)
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
		// Placement runs after renew so the token we send is the one on disk.
		attemptReport(cfg)
		attemptRenew(cfg)
		host, addr, err := resolveDial(cfg)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			backoff = NextBackoff(backoff)
			log.Printf("placement failed: %v; retry in %s", err, backoff)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff):
			}
			continue
		}
		if err := dialAndHeartbeat(ctx, cfg, host, addr); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var rej Rejection
			if errors.As(err, &rej) {
				if rej.Reason == "draining" {
					log.Print(DrainingUserMessage)
					backoff = NextBackoff(backoff)
					select {
					case <-ctx.Done():
						return nil
					case <-time.After(backoff):
					}
					continue
				}
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
	orgDir, err := store.ResolveActiveDir(cfg.CertsDir)
	if err != nil {
		return fmt.Errorf("reload certs: %w", err)
	}
	material, err := store.Load(orgDir)
	if err != nil {
		return fmt.Errorf("reload certs: %w", err)
	}
	tlsCfg, err := material.ClientTLSConfigFor(host)
	if err != nil {
		return err
	}
	tlsCfg = tlsCfg.Clone()
	tlsCfg.NextProtos = []string{"h2"}

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

	sess := &session{
		cfg:    cfg,
		conn:   conn,
		reject: make(chan Rejection, 1),
	}

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	defer close(done)

	go sess.renewLoop(ctx, cfg)

	// IdleTimeout must stay zero: HTTP/2 PING does not count as activity,
	// so a short IdleTimeout would GOAWAY a quiet agent. Liveness is the
	// relay's ClientConn.Ping. ReadIdleTimeout is also zero — we do not
	// want the agent to PING-probe and drop a quiet-but-alive relay.
	h2s := &http2.Server{IdleTimeout: 0}
	h2s.ServeConn(conn, &http2.ServeConnOpts{
		Context: ctx,
		Handler: sess,
	})

	if ctx.Err() != nil {
		return ctx.Err()
	}
	select {
	case rej := <-sess.reject:
		return rej
	default:
	}
	log.Printf("heartbeat dropped relay=%s", host)
	return fmt.Errorf("session closed")
}

func settleRejection(ctx context.Context, cfg Config, rej Rejection) error {
	if rej.Reason == "draining" {
		log.Print(DrainingUserMessage)
		return nil
	}
	if rej.Reason == "revoked" {
		orgID, _ := store.ReadActive(cfg.CertsDir)
		if orgID == "" {
			if dir, err := store.ResolveActiveDir(cfg.CertsDir); err == nil {
				orgID = filepath.Base(dir)
			}
		}
		others := 0
		if orgs, err := store.List(cfg.CertsDir); err == nil {
			for _, o := range orgs {
				if filepath.Base(o.Dir) != orgID && o.ID != orgID {
					others++
				}
			}
		}
		if orgID != "" {
			if err := store.RemoveOrg(cfg.CertsDir, orgID); err != nil {
				log.Printf("could not finish removing credentials: %v", err)
			}
		} else {
			if err := store.ClearEnrollment(cfg.CertsDir); err != nil {
				log.Printf("could not finish removing credentials: %v", err)
			}
			if err := sysinfo.ClearState(cfg.CertsDir); err != nil {
				log.Printf("could not clear system-info state: %v", err)
			}
		}
		if others > 0 {
			log.Print(RevokedOrgMessage)
		} else {
			log.Print(RevokedUserMessage)
		}
	} else {
		log.Printf("this connection was ended (%s). Not retrying. Credentials were kept.", rej.Reason)
	}
	<-ctx.Done()
	return nil
}
