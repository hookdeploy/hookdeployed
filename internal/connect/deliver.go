package connect

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// hopByHop are RFC 7230 hop-by-hop headers plus Host (rewritten to the
// local target so laptop frameworks do not see the relay's authority).
var hopByHop = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Proxy-Connection":    true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
	"Host":                true,
}

type session struct {
	cfg    Config
	conn   net.Conn
	reject chan Rejection
}

func (s *session) localURL() string {
	if s.cfg.LocalURL != "" {
		return s.cfg.LocalURL
	}
	return LocalDeliverURL
}

func (s *session) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == ControlPath {
		s.handleControl(w, r)
		return
	}
	s.handleDeliver(w, r)
}

func (s *session) handleControl(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body)
	w.WriteHeader(http.StatusNoContent)
	if rc := http.NewResponseController(w); rc != nil {
		_ = rc.Flush()
	}
	select {
	case s.reject <- Rejection{Reason: body.Reason}:
	default:
	}
}

func (s *session) handleDeliver(w http.ResponseWriter, r *http.Request) {
	base, err := url.Parse(s.localURL())
	if err != nil {
		log.Printf("local deliver failed: %v", err)
		http.Error(w, "bad local url", http.StatusBadGateway)
		return
	}
	out := *base
	out.Path = r.URL.Path
	out.RawQuery = r.URL.RawQuery

	ctx, cancel := context.WithTimeout(r.Context(), localDeliverTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, r.Method, out.String(), r.Body)
	if err != nil {
		log.Printf("local deliver failed: %v", err)
		http.Error(w, "build request", http.StatusBadGateway)
		return
	}
	copyHeaders(req.Header, r.Header)
	req.Host = base.Host

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("local deliver failed: %v", err)
		http.Error(w, "local request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("local deliver status=%d", resp.StatusCode)
	}
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		if hopByHop[http.CanonicalHeaderKey(k)] {
			continue
		}
		if http.CanonicalHeaderKey(k) == "Connection" {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
	// Honour Connection: <header-name> extras.
	for _, extra := range src.Values("Connection") {
		for _, name := range strings.Split(extra, ",") {
			dst.Del(strings.TrimSpace(name))
		}
	}
}

func (s *session) renewLoop(ctx context.Context, cfg Config) {
	pingEvery := cfg.PingInterval
	if pingEvery <= 0 {
		pingEvery = DefaultPingInterval
	}
	renewEvery := cfg.RenewInterval
	if renewEvery <= 0 {
		renewEvery = DefaultRenewInterval
	}
	wakeTicker := time.NewTicker(pingEvery)
	defer wakeTicker.Stop()
	renewTicker := time.NewTicker(renewEvery)
	defer renewTicker.Stop()
	lastWall := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-wakeTicker.C:
			now := time.Now()
			if IsWakeEvent(lastWall, now, pingEvery) {
				attemptRenew(cfg)
			}
			lastWall = now
		case <-renewTicker.C:
			lastWall = time.Now()
			attemptRenew(cfg)
		}
	}
}
