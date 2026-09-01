package enroll

import (
	"bufio"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/hookdeploy/hookdeployed/internal/store"
)

type deviceIO struct {
	In               io.Reader
	Out              io.Writer
	OpenURL          func(string)
	CheckInteractive func() error
	Client           string
}

func RunDevice(baseURL, certDir string) error {
	return RunDeviceOpts(baseURL, certDir, false, "")
}

// RunDeviceOpts is RunDevice with an explicit -no-tty switch. When noTTY
// is true the TTY check is skipped so a supervising parent (tray) can
// feed the browser code on stdin. The interactive path is unchanged.
// client is an optional identifier (e.g. "agent-gui") sent on device/start.
func RunDeviceOpts(baseURL, certDir string, noTTY bool, client string) error {
	return runDevice(baseURL, certDir, deviceIO{
		In:      os.Stdin,
		Out:     os.Stderr,
		OpenURL: tryOpenURL,
		Client:  client,
		CheckInteractive: func() error {
			if noTTY {
				return nil
			}
			return RequireInteractiveFile(os.Stdin)
		},
	})
}

func runDevice(baseURL, certDir string, io deviceIO) error {
	if io.CheckInteractive != nil {
		if err := io.CheckInteractive(); err != nil {
			return err
		}
	}
	key, keyPEM, err := GenerateKey()
	if err != nil {
		return err
	}
	client := NewClient(baseURL)
	start, err := client.DeviceStart(localHostname(), io.Client)
	if err != nil {
		return err
	}
	if start.VerificationURL == "" {
		return fmt.Errorf("enrollment start missing verification_url")
	}
	PrintEnrollmentURL(io.Out, start.VerificationURL)
	if io.OpenURL != nil {
		io.OpenURL(start.VerificationURL)
	}

	deadline := time.Now().Add(time.Duration(start.ExpiresIn) * time.Second)
	if start.ExpiresIn <= 0 {
		deadline = time.Now().Add(10 * time.Minute)
	}
	interval := 5 * time.Second
	if start.Interval > 0 {
		interval = time.Duration(start.Interval) * time.Second
	}

	var userCode string
	var agentID string
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("enrollment expired")
		}
		if userCode == "" {
			userCode, err = ReadUserCode(io.In, io.Out)
			if err != nil {
				return err
			}
		}
		var csrPEM []byte
		if agentID != "" {
			csrPEM, err = CSRFromKey(key, agentID)
			if err != nil {
				return err
			}
		}
		poll, err := client.DevicePoll(start.DeviceCode, userCode, csrPEM)
		if err != nil {
			if IsInvalidCode(err) {
				fmt.Fprintf(io.Out, "wrong code — try again\n")
				userCode = ""
				continue
			}
			return err
		}
		switch poll.Status {
		case "pending":
			if poll.Interval > 0 {
				interval = time.Duration(poll.Interval) * time.Second
			}
			time.Sleep(interval)
			continue
		case "slow_down":
			interval += 5 * time.Second
			time.Sleep(interval)
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
			orgName := firstNonEmpty(poll.OrgName, poll.Minted.OrgName)
			if err := persistEnrollment(certDir, []byte(poll.Root), []byte(poll.CertChain), []byte(poll.Certificate), []byte(poll.CA), keyPEM, []byte(poll.RenewalToken), store.OrgMeta{
				ID:   firstNonEmpty(poll.OrgID, poll.Minted.OrgID),
				Name: orgName,
				Slug: firstNonEmpty(poll.OrgSlug, poll.Minted.OrgSlug),
			}); err != nil {
				return err
			}
			if orgName != "" {
				fmt.Fprintf(io.Out, "enrolled in %s\n", orgName)
			} else {
				fmt.Fprintf(io.Out, "enrolled\n")
			}
			return nil
		default:
			return fmt.Errorf("unexpected poll status %q", poll.Status)
		}
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func PrintEnrollmentURL(w io.Writer, url string) {
	fmt.Fprintf(w, "Open this URL to enroll this agent:\n  %s\n", url)
}

func RequireInteractiveFile(f *os.File) error {
	if f == nil {
		return fmt.Errorf("enroll needs a terminal to enter the code (stdin is not a TTY). Use -token for scripted enrollment")
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeCharDevice == 0 {
		return fmt.Errorf("enroll needs a terminal to enter the code (stdin is not a TTY). Use -token for scripted enrollment")
	}
	return nil
}

func ReadUserCode(r io.Reader, w io.Writer) (string, error) {
	fmt.Fprint(w, "Enter the code from the browser: ")
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && !(err == io.EOF && strings.TrimSpace(line) != "") {
		if err == io.EOF {
			return "", fmt.Errorf("enroll needs a terminal to enter the code (stdin is not a TTY). Use -token for scripted enrollment")
		}
		return "", err
	}
	code := strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(line)))
	if len(code) != 8 {
		return "", fmt.Errorf("code must be 8 characters")
	}
	return code, nil
}

// tryOpenURL is best-effort. Failure is not an error — the URL is always printed.
func tryOpenURL(raw string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", raw)
	case "darwin":
		cmd = exec.Command("open", raw)
	default:
		cmd = exec.Command("xdg-open", raw)
	}
	_ = cmd.Start()
}

func RunToken(baseURL, token, certDir string) error {
	key, keyPEM, err := GenerateKey()
	if err != nil {
		return err
	}
	client := NewClient(baseURL)
	host := localHostname()
	started, err := client.TokenStart(token, host)
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
	out, err := client.TokenComplete(token, csrPEM, host)
	if err != nil {
		return err
	}
	return persistEnrollment(certDir, []byte(out.Root), []byte(out.CertChain), []byte(out.Certificate), []byte(out.CA), keyPEM, []byte(out.RenewalToken), store.OrgMeta{
		ID:   out.OrgID,
		Name: out.OrgName,
		Slug: out.OrgSlug,
	})
}

func persistEnrollment(root string, rootPEM, certChain, leafPEM, intermediatePEM, keyPEM, renewalToken []byte, meta store.OrgMeta) error {
	if strings.TrimSpace(meta.ID) == "" {
		if id, err := store.OrgIDFromCertPEM(leafPEM); err == nil {
			meta.ID = id
		}
	}
	if strings.TrimSpace(meta.ID) == "" {
		return fmt.Errorf("enrollment missing org id")
	}
	if err := store.EnsureLayout(root); err != nil {
		return err
	}
	orgDir := store.OrgDir(root, meta.ID)
	if err := store.WriteBundle(orgDir, rootPEM, certChain, leafPEM, intermediatePEM, keyPEM, renewalToken); err != nil {
		return err
	}
	if err := store.WriteOrgMeta(orgDir, meta); err != nil {
		return err
	}
	return store.WriteActive(root, meta.ID)
}

func localHostname() string {
	host, err := os.Hostname()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(host)
}

func ShouldRenew(cert *x509.Certificate, now time.Time) bool {
	if cert == nil {
		return false
	}
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return true
	}
	life := cert.NotAfter.Sub(cert.NotBefore)
	if life <= 0 {
		return true
	}
	halfway := cert.NotBefore.Add(life / 2)
	return !now.Before(halfway)
}

func MaybeRenew(baseURL, certDir string) error {
	material, err := store.Load(certDir)
	if err != nil {
		return err
	}
	if !ShouldRenew(material.ClientCert, time.Now()) {
		return nil
	}
	csrPEM, err := CSRFromKey(material.ClientKey, material.ClientCert.Subject.CommonName)
	if err != nil {
		return err
	}
	client := NewClient(baseURL)
	var out *TokenResponse
	if token := strings.TrimSpace(material.RenewalToken); token != "" {
		out, err = client.RenewWithToken(token, csrPEM)
	} else {
		rootPEM, readErr := os.ReadFile(filepath.Join(certDir, "ca.crt"))
		if readErr != nil {
			return readErr
		}
		certPEM, readErr := os.ReadFile(filepath.Join(certDir, "client.crt"))
		if readErr != nil {
			return readErr
		}
		out, err = client.Renew(certPEM, nil, rootPEM, csrPEM)
	}
	if err != nil {
		return err
	}
	if strings.TrimSpace(material.RenewalToken) != "" && strings.TrimSpace(out.RenewalToken) == "" {
		return fmt.Errorf("renew response missing renewal_token")
	}
	keyPEM, err := EncodeKey(material.ClientKey)
	if err != nil {
		return err
	}
	if err := store.WriteBundle(certDir, []byte(out.Root), []byte(out.CertChain), []byte(out.Certificate), []byte(out.CA), keyPEM, []byte(out.RenewalToken)); err != nil {
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
