package enroll

import (
	"net/http"
	"sync"
	"time"
)

// ClockSkewThreshold is how far local time may drift from the enrollment
// worker's Date header before we treat a cert-time dial failure as a clock
// problem. Five minutes is well above normal NTP jitter and below the worker's
// 1h cert grace, so it catches clear misconfiguration without false positives
// from a few seconds of skew.
const ClockSkewThreshold = 5 * time.Minute

var observedServerDate = struct {
	mu   sync.Mutex
	skew time.Duration // localNow - serverTime; positive means local is ahead
	ok   bool
}{}

// NoteResponseDate records skew from an enrollment-worker/relay HTTP Date
// header. No external time authority is contacted — only headers on requests
// the agent already makes.
func NoteResponseDate(h http.Header, now time.Time) {
	raw := h.Get("Date")
	if raw == "" {
		return
	}
	server, err := http.ParseTime(raw)
	if err != nil {
		return
	}
	skew := now.Sub(server)
	observedServerDate.mu.Lock()
	observedServerDate.skew = skew
	observedServerDate.ok = true
	observedServerDate.mu.Unlock()
}

// ObservedClockSkew returns the last noted local-minus-server skew.
func ObservedClockSkew() (skew time.Duration, ok bool) {
	observedServerDate.mu.Lock()
	defer observedServerDate.mu.Unlock()
	return observedServerDate.skew, observedServerDate.ok
}

// ExcessiveClockSkew reports |skew| above ClockSkewThreshold.
func ExcessiveClockSkew() bool {
	skew, ok := ObservedClockSkew()
	if !ok {
		return false
	}
	if skew < 0 {
		skew = -skew
	}
	return skew > ClockSkewThreshold
}

// ResetObservedClockSkew clears noted skew (tests).
func ResetObservedClockSkew() {
	observedServerDate.mu.Lock()
	observedServerDate.ok = false
	observedServerDate.skew = 0
	observedServerDate.mu.Unlock()
}

// SetObservedClockSkewForTest injects skew without an HTTP response.
func SetObservedClockSkewForTest(skew time.Duration) {
	observedServerDate.mu.Lock()
	observedServerDate.skew = skew
	observedServerDate.ok = true
	observedServerDate.mu.Unlock()
}
