package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestSigning(t *testing.T) {

	// Prepare and test a self signed root:

	privateBytes, certBytes := GetSelfSignedCert()
	cert, err := tls.X509KeyPair(certBytes, privateBytes)
	if err != nil {
		t.Fatal(err.Error())
	}

	certificate, err := GetX509Certificate(cert)
	if err != nil {
		t.Fatal(err.Error())
	}

	if err := certificate.VerifyHostname("example.com"); err != nil {
		t.Fatal(err.Error())
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(certificate)

	if _, err := certificate.Verify(x509.VerifyOptions{
		DNSName: "example.com",
		Roots:   certPool,
	}); err != nil {
		t.Fatal(err.Error())
	}

	// Sign another certificate
	child, err := GetSignedCertificate(certificate, cert.PrivateKey, "test1.com")
	if err != nil {
		t.Fatal(err.Error())
	}

	childx509, err := GetX509Certificate(*child)
	if err != nil {
		t.Fatal(err.Error())
	}
	if _, err := childx509.Verify(x509.VerifyOptions{
		DNSName: "test1.com",
		Roots:   certPool,
	}); err != nil {
		t.Fatal(err.Error())
	}

}
