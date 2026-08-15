package store

import (
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

func Write(dir string, caPEM, certPEM, keyPEM []byte) error {
	return mtls.WriteClientDir(dir, caPEM, certPEM, keyPEM)
}

func Load(dir string) (*mtls.ClientMaterial, error) {
	return mtls.LoadClientDir(dir)
}
