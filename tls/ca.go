// Copyright 2016 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// NewCA generates a CA certificate/key pair suitable for signing server
// keys for an environment with the given name. "size" is the number
// of bits.
func NewCA(envName, UUID string, expiry time.Time, size int) (certPEM, keyPEM string, err error) {
	if size <= 0 {
		size = defaultSize
	}

	key, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		return "", "", err
	}
	// TODO(perrito666) 2016-05-02 lp:1558657
	now := time.Now()

	// A serial number can be up to 20 octets in size.
	// https://tools.ietf.org/html/rfc5280#section-4.1.2.2
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 8*20))
	if err != nil {
		return "", "", fmt.Errorf("failed to generate serial number: %s", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("juju-generated CA for model %q", envName),
			Organization: []string{"juju"},
			SerialNumber: UUID,
		},
		NotBefore:             now.UTC().AddDate(0, 0, -7),
		NotAfter:              expiry.UTC(),
		SubjectKeyId:          bigIntHash(key.N),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		MaxPathLen:            0, // Disallow delegation for now.
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return "", "", fmt.Errorf("cannot create certificate: %v", err)
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
