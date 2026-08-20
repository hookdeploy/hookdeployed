package enroll

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/hookdeploy/hookdeployed/internal/store"
)

func TestCSRCNIsAgentID(t *testing.T) {
	agentID := "11111111-2222-4333-8444-555555555555"
	key, keyPEM, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	csrPEM, err := CSRFromKey(key, agentID)
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
	if csr.Subject.CommonName != agentID {
		t.Fatalf("cn=%s want %s", csr.Subject.CommonName, agentID)
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

func TestStepLikeChainReachesRootAndPresentsIntermediate(t *testing.T) {
	chain, err := GenerateStepLikeChain("agent-uuid-here", "org-uuid-here")
	if err != nil {
		t.Fatal(err)
	}
	if err := chain.Leaf.CheckSignatureFrom(chain.Intermediate); err != nil {
		t.Fatalf("leaf not issued by intermediate: %v", err)
	}
	if err := chain.Intermediate.CheckSignatureFrom(chain.Root); err != nil {
		t.Fatalf("intermediate not issued by root: %v", err)
	}
	if err := chain.Leaf.CheckSignatureFrom(chain.Root); err == nil {
		t.Fatal("leaf must NOT be issued by root — that is the step-ca shape")
	}

	dir := t.TempDir()
	keyPEM, err := EncodeKey(chain.LeafKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteBundle(dir, chain.RootPEM, chain.CertChainPEM, chain.LeafPEM, chain.IntermediatePEM, keyPEM, nil); err != nil {
		t.Fatal(err)
	}
	material, err := store.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if material.ClientCert.Subject.CommonName != "agent-uuid-here" {
		t.Fatalf("cn=%s", material.ClientCert.Subject.CommonName)
	}
	if len(material.ClientCert.Subject.OrganizationalUnit) == 0 || material.ClientCert.Subject.OrganizationalUnit[0] != "org-uuid-here" {
		t.Fatal("missing OU")
	}
	if len(material.Intermediates) != 1 {
		t.Fatalf("intermediates=%d want 1 (relay ClientCAs=root needs the intermediate presented)", len(material.Intermediates))
	}
	if material.CACert.Equal(chain.Root) == false {
		t.Fatal("ca.crt must be the root, not the intermediate")
	}
	if material.CACert.Equal(chain.Intermediate) {
		t.Fatal("stored ca.crt is the intermediate — renew/relay will break")
	}
	if material.RenewalToken != "" {
		t.Fatalf("RenewalToken=%q want empty for bundles without a token", material.RenewalToken)
	}

	opts := x509.VerifyOptions{
		Roots:         material.CAPool(),
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	opts.Intermediates.AddCert(material.Intermediates[0])
	if _, err := material.ClientCert.Verify(opts); err != nil {
		t.Fatalf("leaf+intermediate does not verify against stored root: %v", err)
	}
}
