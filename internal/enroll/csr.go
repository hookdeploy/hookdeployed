package enroll

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
)

func GenerateKey() (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := EncodeKey(key)
	if err != nil {
		return nil, nil, err
	}
	return key, keyPEM, nil
}

func EncodeKey(key *ecdsa.PrivateKey) ([]byte, error) {
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	if keyPEM == nil {
		return nil, fmt.Errorf("failed to encode key")
	}
	return keyPEM, nil
}

func CSRFromKey(key *ecdsa.PrivateKey, cn string) ([]byte, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	if err != nil {
		return nil, err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	if csrPEM == nil {
		return nil, fmt.Errorf("failed to encode CSR")
	}
	return csrPEM, nil
}

func GenerateKeyAndCSR(cn string) (key *ecdsa.PrivateKey, csrPEM []byte, keyPEM []byte, err error) {
	key, keyPEM, err = GenerateKey()
	if err != nil {
		return nil, nil, nil, err
	}
	csrPEM, err = CSRFromKey(key, cn)
	if err != nil {
		return nil, nil, nil, err
	}
	return key, csrPEM, keyPEM, nil
}
