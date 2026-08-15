package enroll

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/hookdeploy/hookdeployed/internal/store"
)

func RunDevice(baseURL, orgHint, certDir string) error {
	_, csrPEM, keyPEM, err := GenerateKeyAndCSR("pending")
	if err != nil {
		return err
	}
	client := NewClient(baseURL)
	start, err := client.DeviceStart(csrPEM, orgHint)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "To approve this agent, open:\n  %s\nEnter code: %s\n", start.VerificationURL, start.UserCode)

	deadline := time.Now().Add(time.Duration(start.ExpiresIn) * time.Second)
	interval := time.Duration(start.Interval) * time.Second
	if interval < time.Second {
		interval = 5 * time.Second
	}
	for time.Now().Before(deadline) {
		time.Sleep(interval)
		poll, err := client.DevicePoll(start.DeviceCode)
		if err != nil {
			return err
		}
		switch poll.Status {
		case "pending":
			if poll.Interval > 0 {
				interval = time.Duration(poll.Interval) * time.Second
			}
			continue
		case "slow_down":
			interval += 5 * time.Second
			continue
		case "denied", "expired":
			return fmt.Errorf("enrollment %s", poll.Status)
		case "approved":
			return store.Write(certDir, []byte(poll.CA), []byte(poll.Certificate), keyPEM)
		default:
			return fmt.Errorf("unexpected poll status %q", poll.Status)
		}
	}
	return fmt.Errorf("enrollment expired")
}

func RunToken(baseURL, token, certDir string) error {
	_, csrPEM, keyPEM, err := GenerateKeyAndCSR("pending")
	if err != nil {
		return err
	}
	client := NewClient(baseURL)
	out, err := client.TokenEnroll(token, csrPEM)
	if err != nil {
		return err
	}
	return store.Write(certDir, []byte(out.CA), []byte(out.Certificate), keyPEM)
}

func MaybeRenew(baseURL, certDir string) error {
	material, err := store.Load(certDir)
	if err != nil {
		return err
	}
	life := material.ClientCert.NotAfter.Sub(material.ClientCert.NotBefore)
	halfway := material.ClientCert.NotBefore.Add(life / 2)
	if time.Now().Before(halfway) {
		return nil
	}
	_, csrPEM, keyPEM, err := GenerateKeyAndCSR(material.ClientCert.Subject.CommonName)
	if err != nil {
		return err
	}
	caPEM, err := os.ReadFile(filepath.Join(certDir, "ca.crt"))
	if err != nil {
		return err
	}
	certPEM, err := os.ReadFile(filepath.Join(certDir, "client.crt"))
	if err != nil {
		return err
	}
	client := NewClient(baseURL)
	out, err := client.Renew(certPEM, caPEM, csrPEM)
	if err != nil {
		return err
	}
	return store.Write(certDir, []byte(out.CA), []byte(out.Certificate), keyPEM)
}
