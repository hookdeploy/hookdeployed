package connect

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Stable deliver error identifiers. They ride X-Hd-Error up the chain.
const (
	ErrLocalRefused      = "local_refused"
	ErrLocalError        = "local_error"
	ErrLocalTimeout      = "local_timeout"
	ErrIncompletePayload = "incomplete_payload"
	HeaderError          = "X-Hd-Error"
)

// hopByHop are RFC 7230 hop-by-hop headers plus Host (rewritten to the
// local target so frameworks on the agent's machine do not see the relay's authority).
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

func writeDeliverErr(w http.ResponseWriter, status int, code string) {
	w.Header().Set(HeaderError, code)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, code)
}

type countingReader struct {
	r io.ReadCloser
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func (c *countingReader) Close() error {
	if c.r == nil {
		return nil
	}
	return c.r.Close()
}

func (s *session) handleDeliver(w http.ResponseWriter, r *http.Request) {
	base, err := url.Parse(s.localURL())
	if err != nil {
		log.Printf("local deliver error=write_failed")
		writeDeliverErr(w, http.StatusBadGateway, "write_failed")
		return
	}
	out := *base
	out.Path = r.URL.Path
	out.RawQuery = r.URL.RawQuery

	ctx, cancel := context.WithTimeout(r.Context(), localDeliverTimeout)
	defer cancel()
	counted := &countingReader{r: r.Body}
	req, err := http.NewRequestWithContext(ctx, r.Method, out.String(), counted)
	if err != nil {
		log.Printf("local deliver error=write_failed")
		writeDeliverErr(w, http.StatusBadGateway, "write_failed")
		return
	}
	copyHeaders(req.Header, r.Header)
	req.Host = base.Host
	// NewRequest leaves ContentLength 0 for an arbitrary io.Reader
	// (countingReader), so the transport would chunk. Propagate the
	// inbound length when known. The client writes Content-Length from
	// this field (Request.outgoingLength); Header["Content-Length"] is
	// ignored on the way out — do not set both.
	if r.ContentLength > 0 {
		req.ContentLength = r.ContentLength
	}

	resp, err := http.DefaultClient.Do(req)
	declared := r.ContentLength
	written := counted.n
	mismatch := declared > 0 && written != declared

	if err != nil {
		code := classifyLocalErr(err)
		if mismatch && code != ErrLocalRefused && code != ErrLocalTimeout {
			code = ErrIncompletePayload
		}
		status := http.StatusBadGateway
		if code == ErrLocalTimeout {
			status = http.StatusGatewayTimeout
		}
		log.Printf("local deliver error=%s declared=%d written=%d", code, declared, written)
		writeDeliverErr(w, status, code)
		return
	}
	defer resp.Body.Close()

	if mismatch && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		log.Printf("local deliver error=%s declared=%d written=%d local_status=%d",
			ErrIncompletePayload, declared, written, resp.StatusCode)
		writeDeliverErr(w, http.StatusBadGateway, ErrIncompletePayload)
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if mismatch {
			log.Printf("local deliver error=%s declared=%d written=%d local_status=%d incomplete=1",
				ErrLocalError, declared, written, resp.StatusCode)
		} else {
			log.Printf("local deliver error=%s status=%d", ErrLocalError, resp.StatusCode)
		}
		copyHeaders(w.Header(), resp.Header)
		w.Header().Set(HeaderError, ErrLocalError)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		return
	}

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func classifyLocalErr(err error) string {
	if err == nil {
		return ErrIncompletePayload
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrLocalTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return ErrLocalTimeout
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded") {
		return ErrLocalTimeout
	}
	if strings.Contains(msg, "connection refused") || strings.Contains(msg, "actively refused") {
		return ErrLocalRefused
	}
	var op *net.OpError
	if errors.As(err, &op) {
		low := strings.ToLower(op.Error())
		if strings.Contains(low, "refused") {
			return ErrLocalRefused
		}
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return ErrIncompletePayload
	}
	if strings.Contains(msg, "unexpected eof") ||
		strings.Contains(msg, "stream closed") ||
		strings.Contains(msg, "stream reset") ||
		strings.Contains(msg, "connection reset") {
		return ErrIncompletePayload
	}
	if strings.Contains(msg, "contentlength=") {
		return ErrIncompletePayload
	}
	// "connect" is a prefix of "connection broken" (the Content-Length
	// mismatch wording). Only treat real dial failures as refused.
	if strings.Contains(msg, "dial tcp") || strings.Contains(msg, "dial udp") ||
		strings.Contains(msg, "connectex") {
		return ErrLocalRefused
	}
	return ErrIncompletePayload
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		ck := http.CanonicalHeaderKey(k)
		if hopByHop[ck] {
			continue
		}
		if ck == "Connection" {
			continue
		}
		// Transport metadata (x-hd-*) rides the HTTP/2 session so the
		// next pass can honor target.port. It must not reach the local service.
		if strings.HasPrefix(ck, "X-Hd-") {
			continue
		}
		if ck == "Content-Length" {
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
