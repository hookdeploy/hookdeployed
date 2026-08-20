package enroll

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// StepLikeChain matches step-ca 0.30 SignResponse shape:
// leaf signed by intermediate, intermediate signed by root.
// Sign `ca` / certChain[1] = intermediate. Root is not in the sign body.
type StepLikeChain struct {
	RootPEM         []byte
	IntermediatePEM []byte
	LeafPEM         []byte
	CertChainPEM    []byte
	RootFingerprint string
	Leaf            *x509.Certificate
	Intermediate    *x509.Certificate
	Root            *x509.Certificate
	LeafKey         *ecdsa.PrivateKey
}

func GenerateStepLikeChain(cn, ou string) (*StepLikeChain, error) {
	now := time.Now()
	return GenerateStepLikeChainWindow(cn, ou, now.Add(-time.Hour), now.Add(10*365*24*time.Hour))
}

func GenerateStepLikeChainWindow(cn, ou string, notBefore, notAfter time.Time) (*StepLikeChain, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "HookDeploy Root CA"},
		NotBefore:             notBefore.Add(-time.Hour),
		NotAfter:              notAfter.Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, err
	}

	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	intTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "HookDeploy Intermediate CA"},
		NotBefore:             notBefore.Add(-time.Hour),
		NotAfter:              notAfter.Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	intDER, err := x509.CreateCertificate(rand.Reader, intTmpl, root, &intKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	intermediate, err := x509.ParseCertificate(intDER)
	if err != nil {
		return nil, err
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: cn, OrganizationalUnit: []string{ou}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, intermediate, &leafKey.PublicKey, intKey)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, err
	}

	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	intPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intDER})
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	if rootPEM == nil || intPEM == nil || leafPEM == nil {
		return nil, fmt.Errorf("encode pem")
	}
	sum := sha256.Sum256(root.Raw)
	return &StepLikeChain{
		RootPEM:         rootPEM,
		IntermediatePEM: intPEM,
		LeafPEM:         leafPEM,
		CertChainPEM:    append(append([]byte{}, leafPEM...), intPEM...),
		RootFingerprint: hex.EncodeToString(sum[:]),
		Leaf:            leaf,
		Intermediate:    intermediate,
		Root:            root,
		LeafKey:         leafKey,
	}, nil
}
