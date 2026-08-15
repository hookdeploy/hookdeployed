package enroll

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
)

func TestCSRIsEC(t *testing.T) {
	_, csrPEM, keyPEM, err := GenerateKeyAndCSR("pending")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("csr pem")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "pending" {
		t.Fatalf("cn=%s", csr.Subject.CommonName)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		t.Fatal("key pem")
	}
	if _, err := x509.ParseECPrivateKey(keyBlock.Bytes); err != nil {
		t.Fatal(err)
	}
}

func TestOUProofFixture(t *testing.T) {
	pemBytes := os.Getenv("ENROLLMENT_OU_PROOF_CERT")
	if pemBytes == "" {
		t.Skip("SKIP: set ENROLLMENT_OU_PROOF_CERT to a minted leaf PEM to assert CN+OU (needs Infisical/CA)")
	}
	block, _ := pem.Decode([]byte(pemBytes))
	if block == nil {
		t.Fatal("not a PEM cert")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName == "" {
		t.Fatal("missing CN")
	}
	if len(cert.Subject.OrganizationalUnit) == 0 || cert.Subject.OrganizationalUnit[0] == "" {
		t.Fatal("missing OU — relay will reject")
	}
}
