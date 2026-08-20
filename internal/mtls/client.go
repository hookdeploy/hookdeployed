package mtls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ClientMaterial is the enrolled-agent subset.
//
//	CACert         = HookDeploy ROOT (same object the relay puts in ClientCAs)
//	ClientCert     = leaf
//	Intermediates  = issuing intermediate(s) presented during the handshake
//	ClientKey      = agent private key
//
// Relay ClientCAs = root is satisfied because the agent sends leaf+intermediate
// and the relay builds leaf → intermediate → root.
type ClientMaterial struct {
	CACert        *x509.Certificate
	ClientCert    *x509.Certificate
	Intermediates []*x509.Certificate
	ClientKey     *ecdsa.PrivateKey
	// RenewalToken is the raw hd_agentrenew_… secret from renewal.token.
	// Empty when the file is absent (agents enrolled before this field).
	RenewalToken string
}

func (c *ClientMaterial) CAPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(c.CACert)
	return pool
}

func (c *ClientMaterial) ClientTLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{certChainAndKey(c.ClientCert, c.Intermediates, c.ClientKey)},
		RootCAs:      c.CAPool(),
		ServerName:   DefaultServerName,
		MinVersion:   tls.VersionTLS13,
	}
}

// ClientTLSConfigFor is the production dial config. ServerName must be the
// relay hostname (SAN), not localhost. Echo/stub keep using ClientTLSConfig().
func (c *ClientMaterial) ClientTLSConfigFor(serverName string) (*tls.Config, error) {
	if strings.TrimSpace(serverName) == "" {
		return nil, fmt.Errorf("server name is required")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{certChainAndKey(c.ClientCert, c.Intermediates, c.ClientKey)},
		RootCAs:      c.CAPool(),
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

func certChainAndKey(leaf *x509.Certificate, intermediates []*x509.Certificate, key interface{}) tls.Certificate {
	ders := [][]byte{leaf.Raw}
	for _, i := range intermediates {
		ders = append(ders, i.Raw)
	}
	return tls.Certificate{
		Certificate: ders,
		PrivateKey:  key,
		Leaf:        leaf,
	}
}

func LoadClientDir(dir string) (*ClientMaterial, error) {
	caCert, err := loadCert(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, err
	}
	chain, err := loadCerts(filepath.Join(dir, "client.crt"))
	if err != nil {
		return nil, err
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("%s: no certificate PEM", filepath.Join(dir, "client.crt"))
	}
	clientKey, err := loadKey(filepath.Join(dir, "client.key"))
	if err != nil {
		return nil, err
	}
	renewalToken, err := loadOptionalSecret(filepath.Join(dir, "renewal.token"))
	if err != nil {
		return nil, err
	}
	return &ClientMaterial{
		CACert:        caCert,
		ClientCert:    chain[0],
		Intermediates: chain[1:],
		ClientKey:     clientKey,
		RenewalToken:  renewalToken,
	}, nil
}

func WriteClientDir(dir string, caPEM, certPEM, keyPEM, renewalToken []byte) error {
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
	if len(bytes.TrimSpace(renewalToken)) == 0 {
		return nil
	}
	path := filepath.Join(dir, "renewal.token")
	if err := os.WriteFile(path, bytes.TrimSpace(renewalToken), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func loadCerts(path string) ([]*x509.Certificate, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("%s: no certificate PEM", path)
	}
	return certs, nil
}

func loadOptionalSecret(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return string(bytes.TrimSpace(raw)), nil
}
