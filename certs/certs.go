package certs

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

type CertificateSet struct {
	domainCerts map[string]tls.Certificate
	lock        sync.Mutex
	rootCert    *x509.Certificate
	rootPrivate crypto.PrivateKey
}

func NewCertificateSet(root tls.Certificate) (*CertificateSet, error) {

	rootCert, err := GetX509Certificate(root)
	if err != nil {
		return nil, err
	}
	return &CertificateSet{
		domainCerts: map[string]tls.Certificate{},
		rootCert:    rootCert,
		rootPrivate: root.PrivateKey,
	}, nil
}

func (c *CertificateSet) ForDomain(hostname string) (*tls.Certificate, error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if cert, ok := c.domainCerts[hostname]; ok {
		return &cert, nil
	}

	cert, err := GetSignedCertificate(c.rootCert, c.rootPrivate, strings.Split(hostname, ":")[0])
	if err != nil {
		return nil, err
	}

	c.domainCerts[hostname] = *cert
	return cert, nil
}

func GetX509Certificate(cert tls.Certificate) (*x509.Certificate, error) {
	certificates, err := x509.ParseCertificates(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	if len(certificates) != 1 {
		return nil, fmt.Errorf("%d certificates", len(certificates))
	}

	certificate := certificates[0]
	return certificate, nil
}

func GetSignedCertificate(rootCert *x509.Certificate, rootPrivate crypto.PrivateKey, domain string) (*tls.Certificate, error) {

	serverPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(serverPrivateKey)
	serverPublicKey := serverPrivateKey.Public()

	serverCSRBytes, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, serverPrivateKey)
	if err != nil {
		return nil, err
	}
	serverCSR, err := x509.ParseCertificateRequest(serverCSRBytes)
	if err != nil {
		return nil, err
	}

	signedSubject := pkix.Name{
		CommonName: domain,
	}

	certTemplate := &x509.Certificate{
		Signature:          serverCSR.Signature,
		SignatureAlgorithm: serverCSR.SignatureAlgorithm,

		PublicKeyAlgorithm: serverCSR.PublicKeyAlgorithm,
		PublicKey:          serverCSR.PublicKey,

		SerialNumber: big.NewInt(2),
		Issuer:       rootCert.Subject,
		Subject:      signedSubject,
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, rootCert, serverPublicKey, rootPrivate)

	pair, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certBytes,
		}),
		pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyBytes,
		}),
	)

	if err != nil {
		return nil, err
	}
	return &pair, nil

}

func GetSelfSignedCert() ([]byte, []byte) {

	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1653),
		Subject: pkix.Name{
			Organization:  []string{"ORGANIZATION_NAME"},
			Country:       []string{"COUNTRY_CODE"},
			Province:      []string{"PROVINCE"},
			Locality:      []string{"CITY"},
			StreetAddress: []string{"ADDRESS"},
			PostalCode:    []string{"POSTAL_CODE"},
			CommonName:    "example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := &priv.PublicKey
	certBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, priv)
	if err != nil {
		panic(err)
	}

	return pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		}), pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certBytes,
		})

}
