package mtls

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
)

// ClientMaterial is the enrolled-agent subset: CA trust + client cert/key.
// Unlike LoadDir this does not require ca.key or server PEMs.
type ClientMaterial struct {
	CACert     *x509.Certificate
	ClientCert *x509.Certificate
	ClientKey  *ecdsa.PrivateKey
}

func (c *ClientMaterial) CAPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(c.CACert)
	return pool
}

func (c *ClientMaterial) ClientTLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{certAndKey(c.ClientCert, c.ClientKey)},
		RootCAs:      c.CAPool(),
		ServerName:   DefaultServerName,
		MinVersion:   tls.VersionTLS13,
	}
}

func LoadClientDir(dir string) (*ClientMaterial, error) {
	caCert, err := loadCert(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, err
	}
	clientCert, err := loadCert(filepath.Join(dir, "client.crt"))
	if err != nil {
		return nil, err
	}
	clientKey, err := loadKey(filepath.Join(dir, "client.key"))
	if err != nil {
		return nil, err
	}
	return &ClientMaterial{
		CACert:     caCert,
		ClientCert: clientCert,
		ClientKey:  clientKey,
	}, nil
}

func WriteClientDir(dir string, caPEM, certPEM, keyPEM []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	files := []struct {
		name string
		pem  []byte
	}{
		{"ca.crt", caPEM},
		{"client.crt", certPEM},
		{"client.key", keyPEM},
	}
	for _, f := range files {
		path := filepath.Join(dir, f.name)
		if err := os.WriteFile(path, f.pem, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}
	return nil
}
