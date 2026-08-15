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
//	ca.crt     = HookDeploy ROOT (relay ClientCAs / agent RootCAs)
//	client.crt = leaf + intermediate (what TLS presents to the relay)
//	client.key = agent private key (0600)
//
// step-ca's sign `ca` field is the intermediate, not the root. Prefer `root`
// from the worker (GET /1.0/root/{sha}). certChain is [leaf, intermediate].
func WriteBundle(dir string, rootPEM, certChain, leafPEM, intermediatePEM, keyPEM []byte) error {
	root := bytes.TrimSpace(rootPEM)
	chain := bytes.TrimSpace(certChain)
	if len(chain) == 0 {
		chain = bytes.Join([][]byte{bytes.TrimSpace(leafPEM), bytes.TrimSpace(intermediatePEM)}, []byte("\n"))
	}
	if len(root) == 0 {
		return os.ErrInvalid
	}
	return mtls.WriteClientDir(dir, root, chain, keyPEM)
}

func Write(dir string, caPEM, certPEM, keyPEM []byte) error {
	return mtls.WriteClientDir(dir, caPEM, certPEM, keyPEM)
}

func Load(dir string) (*mtls.ClientMaterial, error) {
	return mtls.LoadClientDir(dir)
}
