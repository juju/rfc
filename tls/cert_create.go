// Copyright 2016 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/juju/errors"
)

const defaultSize = 2048

// NewDefaultServer generates a certificate/key pair suitable for use by a server, with an
// expiry time of 10 years.
func NewDefaultServer(caCertPEM, caKeyPEM string, hostnames []string, size int) (certPEM, keyPEM string, err error) {
	// TODO(perrito666) 2016-05-02 lp:1558657
	expiry := time.Now().UTC().AddDate(10, 0, 0)
	return newLeaf(caCertPEM, caKeyPEM, expiry, hostnames, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, size)
}

// NewServer generates a certificate/key pair suitable for use by a server.
func NewServer(caCertPEM, caKeyPEM string, expiry time.Time, hostnames []string, size int) (certPEM, keyPEM string, err error) {
	return newLeaf(caCertPEM, caKeyPEM, expiry, hostnames, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, size)
}

// newLeaf generates a certificate/key pair suitable for use by a leaf node.
func newLeaf(caCertPEM, caKeyPEM string, expiry time.Time, hostnames []string, extKeyUsage []x509.ExtKeyUsage, size int) (certPEM, keyPEM string, err error) {
	if size <= 0 {
		size = defaultSize
	}

	tlsCert, err := tls.X509KeyPair([]byte(caCertPEM), []byte(caKeyPEM))
	if err != nil {
		return "", "", errors.Trace(err)
	}
	if len(tlsCert.Certificate) != 1 {
		return "", "", fmt.Errorf("more than one certificate for CA")
	}
	caCert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return "", "", errors.Trace(err)
	}
	if !caCert.BasicConstraintsValid || !caCert.IsCA {
		return "", "", errors.Errorf("CA certificate is not a valid CA")
	}
	caKey, ok := tlsCert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return "", "", errors.Errorf("CA private key has unexpected type %T", tlsCert.PrivateKey)
	}
	key, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		return "", "", errors.Errorf("cannot generate key: %v", err)
	}
	// TODO(perrito666) 2016-05-02 lp:1558657
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: new(big.Int),
		Subject: pkix.Name{
			// This won't match host names with dots. The hostname
			// is hardcoded when connecting to avoid the issue.
			CommonName:   "*",
			Organization: []string{"juju"},
		},
		NotBefore: now.UTC().AddDate(0, 0, -7),
		NotAfter:  expiry.UTC(),

		SubjectKeyId: bigIntHash(key.N),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:  extKeyUsage,
	}
	for _, hostname := range hostnames {
		if ip := net.ParseIP(hostname); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, hostname)
		}
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return "", "", err
	}
	certPEMData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	keyPEMData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return string(certPEMData), string(keyPEMData), nil
}

func bigIntHash(n *big.Int) []byte {
	h := sha1.New()
	h.Write(n.Bytes())
	return h.Sum(nil)
}
