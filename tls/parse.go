// Copyright 2016 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package tls

import (
	"fmt"

	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"

	"github.com/juju/errors"
)

// ParseCert parses the given PEM-formatted X509 certificate.
func ParseCert(certPEM string) (*x509.Certificate, error) {
	certPEMData := []byte(certPEM)
	for len(certPEMData) > 0 {
		var certBlock *pem.Block
		certBlock, certPEMData = pem.Decode(certPEMData)
		if certBlock == nil {
			break
		}
		if certBlock.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(certBlock.Bytes)
			return cert, errors.Trace(err)
		}
	}
	return nil, errors.Errorf("no certificates found")
}

// ParseCertAndKey parses the given PEM-formatted X509 certificate
// and RSA private key.
func ParseCertAndKey(certPEM, keyPEM string) (*x509.Certificate, *rsa.PrivateKey, error) {
	tlsCert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, nil, err
	}

	key, ok := tlsCert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("private key with unexpected type %T", key)
	}
	return cert, key, nil
}
