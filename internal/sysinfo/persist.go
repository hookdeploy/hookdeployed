package sysinfo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// RetryInterval is the floor between failed (or repeated) report attempts
// so a reconnect loop cannot hammer the Worker when the snapshot is absent.
const RetryInterval = 5 * time.Minute

// snapshot is the last successful report plus the last attempt clock.
type snapshot struct {
	AgentID         string `json:"agent_id"`
	Sent            *Info  `json:"sent"`
	LastAttemptUnix int64  `json:"last_attempt_unix,omitempty"`
}

// StatePath is the non-secret change-detection file. It lives next to the
// cert directory, not inside it: the cert store is 0700/0600 PKI material
// (ca.crt, client.crt, client.key, renewal.token). Default layout:
//
//	{UserConfigDir}/hookdeploy/certs          ← cert store
//	{UserConfigDir}/hookdeploy/system-info.json
func StatePath(certsDir string) string {
	return filepath.Join(filepath.Dir(certsDir), "system-info.json")
}

func loadSnapshot(path string) (snapshot, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return snapshot{}, nil
		}
		return snapshot{}, err
	}
	var s snapshot
	if err := json.Unmarshal(raw, &s); err != nil {
		return snapshot{}, nil
	}
	return s, nil
}

func writeSnapshot(path string, s snapshot) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o644)
}

// shouldSend reports whether current differs from the last successful send
// (or no successful send exists) and the retry floor has elapsed.
func shouldSend(s snapshot, agentID string, current Info, now time.Time) bool {
	same := s.AgentID == agentID && s.Sent != nil && s.Sent.equal(current)
	if same {
		return false
	}
	if s.LastAttemptUnix == 0 {
		return true
	}
	last := time.Unix(s.LastAttemptUnix, 0)
	return now.Sub(last) >= RetryInterval
}

func markAttempt(s snapshot, now time.Time) snapshot {
	s.LastAttemptUnix = now.Unix()
	return s
}

func markSent(agentID string, info Info, now time.Time) snapshot {
	cp := info
	return snapshot{
		AgentID:         agentID,
		Sent:            &cp,
		LastAttemptUnix: now.Unix(),
	}
}
