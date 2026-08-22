package store

import (
	"bytes"
	"os"
	"path/filepath"

	"github.com/hookdeploy/hookdeployed/internal/mtls"
)

func DefaultDir() string {
	if env := os.Getenv("HOOKDEPLOY_CERT_DIR"); env != "" {
		return env
	}
	home, err := os.UserConfigDir()
	if err != nil || home == "" {
		return "certs"
	}
	return filepath.Join(home, "hookdeploy", "certs")
}

// WriteBundle stores:
//
//	ca.crt         = HookDeploy ROOT (relay ClientCAs / agent RootCAs)
//	client.crt     = leaf + intermediate (what TLS presents to the relay)
//	client.key     = agent private key (0600)
//	renewal.token  = opaque 30-day renewal secret (0600), omitted when empty
//
// step-ca's sign `ca` field is the intermediate, not the root. Prefer `root`
// from the worker (GET /1.0/root/{sha}). certChain is [leaf, intermediate].
// An empty renewalToken leaves an existing renewal.token file untouched.
// When a token is provided, WriteClientDir writes it BEFORE the cert files
// so a cert-write failure after rotation is recoverable (new token, old certs)
// instead of looking like reuse (new certs, stale token).
func WriteBundle(dir string, rootPEM, certChain, leafPEM, intermediatePEM, keyPEM, renewalToken []byte) error {
	root := bytes.TrimSpace(rootPEM)
	chain := bytes.TrimSpace(certChain)
	if len(chain) == 0 {
		chain = bytes.Join([][]byte{bytes.TrimSpace(leafPEM), bytes.TrimSpace(intermediatePEM)}, []byte("\n"))
	}
	if len(root) == 0 {
		return os.ErrInvalid
	}
	return mtls.WriteClientDir(dir, root, chain, keyPEM, renewalToken)
}

func Write(dir string, caPEM, certPEM, keyPEM []byte) error {
	return mtls.WriteClientDir(dir, caPEM, certPEM, keyPEM, nil)
}

func Load(dir string) (*mtls.ClientMaterial, error) {
	return mtls.LoadClientDir(dir)
}

// EnrollmentFiles is the cert-store set that makes an agent enrolled.
// ClearEnrollment deletes them in this order: client.key first so a
// partial failure cannot leave a usable identity (no private key).
var EnrollmentFiles = []string{"client.key", "client.crt", "renewal.token", "ca.crt"}

// ClearEnrollment removes every enrollment file. client.key is removed
// first: without the private key the remaining files are inert.
// Missing files are ignored. The first real remove error is returned
// after the remaining names are still attempted.
func ClearEnrollment(dir string) error {
	var first error
	for _, name := range EnrollmentFiles {
		err := os.Remove(filepath.Join(dir, name))
		if err != nil && !os.IsNotExist(err) && first == nil {
			first = err
		}
	}
	return first
}
