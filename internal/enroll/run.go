package enroll

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/hookdeploy/hookdeployed/internal/store"
)

func RunDevice(baseURL, orgHint, certDir string) error {
	key, keyPEM, err := GenerateKey()
	if err != nil {
		return err
	}
	client := NewClient(baseURL)
	start, err := client.DeviceStart(orgHint)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "To approve this agent, open:\n  %s\nEnter code: %s\n", start.VerificationURL, start.UserCode)

	deadline := time.Now().Add(time.Duration(start.ExpiresIn) * time.Second)
	interval := time.Duration(start.Interval) * time.Second
	if interval < time.Second {
		interval = 5 * time.Second
	}

	var agentID string
	for time.Now().Before(deadline) {
		time.Sleep(interval)
		var csrPEM []byte
		if agentID != "" {
			csrPEM, err = CSRFromKey(key, agentID)
			if err != nil {
				return err
			}
		}
		poll, err := client.DevicePoll(start.DeviceCode, csrPEM)
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
			if poll.Certificate == "" {
				if poll.AgentID == "" {
					return fmt.Errorf("approved poll missing agent_id")
				}
				agentID = poll.AgentID
				continue
			}
			return store.WriteBundle(certDir, []byte(poll.Root), []byte(poll.CertChain), []byte(poll.Certificate), []byte(poll.CA), keyPEM, []byte(poll.RenewalToken))
		default:
			return fmt.Errorf("unexpected poll status %q", poll.Status)
		}
	}
	return fmt.Errorf("enrollment expired")
}

func RunToken(baseURL, token, certDir string) error {
	key, keyPEM, err := GenerateKey()
	if err != nil {
		return err
	}
	client := NewClient(baseURL)
	started, err := client.TokenStart(token)
	if err != nil {
		return err
	}
	if started.AgentID == "" {
		return fmt.Errorf("token start missing agent_id")
	}
	csrPEM, err := CSRFromKey(key, started.AgentID)
	if err != nil {
		return err
	}
	out, err := client.TokenComplete(token, csrPEM)
	if err != nil {
		return err
	}
	return store.WriteBundle(certDir, []byte(out.Root), []byte(out.CertChain), []byte(out.Certificate), []byte(out.CA), keyPEM, []byte(out.RenewalToken))
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
	csrPEM, err := CSRFromKey(material.ClientKey, material.ClientCert.Subject.CommonName)
	if err != nil {
		return err
	}
	rootPEM, err := os.ReadFile(filepath.Join(certDir, "ca.crt"))
	if err != nil {
		return err
	}
	certPEM, err := os.ReadFile(filepath.Join(certDir, "client.crt"))
	if err != nil {
		return err
	}
	client := NewClient(baseURL)
	out, err := client.Renew(certPEM, nil, rootPEM, csrPEM)
	if err != nil {
		return err
	}
	keyPEM, err := EncodeKey(material.ClientKey)
	if err != nil {
		return err
	}
	if err := store.WriteBundle(certDir, []byte(out.Root), []byte(out.CertChain), []byte(out.Certificate), []byte(out.CA), keyPEM, nil); err != nil {
		return err
	}
	logRenewedLeaf(out.Certificate)
	return nil
}

func logRenewedLeaf(certPEM string) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		log.Printf("renewed leaf")
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Printf("renewed leaf")
		return
	}
	log.Printf("renewed leaf not_after=%s", cert.NotAfter.UTC().Format(time.RFC3339))
}
