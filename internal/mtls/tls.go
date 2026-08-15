package mtls

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	DefaultListenAddr = "127.0.0.1:8443"
	DefaultServerName = "localhost"
)

func (p *PKI) CAPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.CACert)
	return pool
}

func (p *PKI) ServerTLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{certAndKey(p.ServerCert, p.ServerKey)},
		ClientCAs:    p.CAPool(),
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
}

func (p *PKI) ClientTLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{certAndKey(p.ClientCert, p.ClientKey)},
		RootCAs:      p.CAPool(),
		ServerName:   DefaultServerName,
		MinVersion:   tls.VersionTLS13,
	}
}

func certAndKey(cert *x509.Certificate, key interface{}) tls.Certificate {
	return tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
		Leaf:        cert,
	}
}

func LoadDir(dir string) (*PKI, error) {
	caCert, err := loadCert(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, err
	}
	caKey, err := loadKey(filepath.Join(dir, "ca.key"))
	if err != nil {
		return nil, err
	}
	serverCert, err := loadCert(filepath.Join(dir, "server.crt"))
	if err != nil {
		return nil, err
	}
	serverKey, err := loadKey(filepath.Join(dir, "server.key"))
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
	return &PKI{
		CACert:     caCert,
		CAKey:      caKey,
		ServerCert: serverCert,
		ServerKey:  serverKey,
		ClientCert: clientCert,
		ClientKey:  clientKey,
	}, nil
}

func loadCert(path string) (*x509.Certificate, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s: no certificate PEM", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

func loadKey(path string) (*ecdsa.PrivateKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("%s: no key PEM", path)
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

// ClientIdentity returns CN and joined OU from the first peer certificate.
func ClientIdentity(state tls.ConnectionState) (cn string, ou string, err error) {
	if len(state.PeerCertificates) == 0 {
		return "", "", fmt.Errorf("no peer certificates")
	}
	sub := state.PeerCertificates[0].Subject
	return sub.CommonName, strings.Join(sub.OrganizationalUnit, ","), nil
}
