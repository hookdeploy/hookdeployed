package sysinfo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/hookdeploy/hookdeployed/internal/store"
)

const reportPath = "/v1/agents/system-info"

// MaybeReport sends host metadata when it differs from the last successful
// report (or no snapshot exists). Failures are returned for the caller to
// log; this function never logs the renewal token.
func MaybeReport(enrollURL, certDir string) error {
	return maybeReport(enrollURL, certDir, Collect, time.Now)
}

func maybeReport(enrollURL, certDir string, collect func() Info, now func() time.Time) error {
	material, err := store.Load(certDir)
	if err != nil {
		return err
	}
	token := strings.TrimSpace(material.RenewalToken)
	if token == "" {
		log.Printf("system-info skipped: no renewal token")
		return nil
	}
	agentID := material.ClientCert.Subject.CommonName
	info := collect()

	path := StatePath(certDir)
	prev, err := loadSnapshot(path)
	if err != nil {
		return err
	}
	if !shouldSend(prev, agentID, info, now()) {
		return nil
	}

	if err := writeSnapshot(path, markAttempt(prev, now())); err != nil {
		log.Printf("system-info state write failed: %v", err)
	}

	if err := postReport(enrollURL, token, info); err != nil {
		return err
	}
	if err := writeSnapshot(path, markSent(agentID, info, now())); err != nil {
		log.Printf("system-info state write failed: %v", err)
	}
	log.Printf("system-info reported os=%s arch=%s", info.OS, info.Arch)
	return nil
}

func postReport(enrollURL, token string, info Info) error {
	body, err := json.Marshal(struct {
		RenewalToken string `json:"renewal_token"`
		Info
	}{RenewalToken: token, Info: info})
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Post(strings.TrimRight(enrollURL, "/")+reportPath, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("system-info: request failed")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("system-info: %s", resp.Status)
	}
	return nil
}
