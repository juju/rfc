// Copyright 2012, 2013 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package tlstest

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/juju/juju/cert"
)

func init() {
	if err := verifyCertificates(); err != nil {
		panic(err)
	}
}

// CACert and CAKey make up a CA key pair.
// CACertX509 and CAKeyRSA hold their parsed equivalents.
// ServerCert and ServerKey hold a CA-signed server cert/key.
// Certs holds the certificates and keys required to make a secure
// connection to a Mongo database.
var (
	CACert, CAKey = mustNewCA()

	CACertX509, CAKeyRSA = mustParseCertAndKey(CACert, CAKey)

	ServerCert, ServerKey = mustNewServer()

	Certs = serverCerts()

	// Other valid test certs different from the default.
	OtherCACert, OtherCAKey = mustNewCA()
)

// CertData holds the certificates and keys required to make a secure
// SSL connection.
type CertData struct {
	// CACert holds the CA certificate. This must certify the private key that
	// was used to sign the server certificate.
	CACert *x509.Certificate

	// ServerCert holds the certificate that certifies the server's
	// private key.
	ServerCert *x509.Certificate

	// ServerKey holds the server's private key.
	ServerKey *rsa.PrivateKey
}

func verifyCertificates() error {
	_, err := tls.X509KeyPair([]byte(CACert), []byte(CAKey))
	if err != nil {
		return fmt.Errorf("bad CA cert key pair: %v", err)
	}
	_, err = tls.X509KeyPair([]byte(ServerCert), []byte(ServerKey))
	if err != nil {
		return fmt.Errorf("bad server cert key pair: %v", err)
	}
	return cert.Verify(ServerCert, CACert, time.Now())
}

func mustNewCA() (string, string) {
	cert.KeyBits = 512
	caCert, caKey, err := cert.NewCA("juju testing", "1234-ABCD-IS-NOT-A-REAL-UUID", time.Now().AddDate(10, 0, 0))
	if err != nil {
		panic(err)
	}
	return string(caCert), string(caKey)
}

func mustNewServer() (string, string) {
	cert.KeyBits = 512
	var hostnames []string
	srvCert, srvKey, err := cert.NewServer(CACert, CAKey, time.Now().AddDate(10, 0, 0), hostnames)
	if err != nil {
		panic(err)
	}
	return string(srvCert), string(srvKey)
}

func mustParseCertAndKey(certPEM, keyPEM string) (*x509.Certificate, *rsa.PrivateKey) {
	cert, key, err := cert.ParseCertAndKey(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return cert, key
}

func serverCerts() *CertData {
	serverCert, serverKey := mustParseCertAndKey(ServerCert, ServerKey)
	return &CertData{
		CACert:     CACertX509,
		ServerCert: serverCert,
		ServerKey:  serverKey,
	}
}
