// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package tls

import (
	"crypto/x509"
	"time"

	"github.com/juju/errors"
)

// Verify verifies that the given server certificate is valid with
// respect to the given CA certificate at the given time.
func Verify(srvCertPEM, caCertPEM string, when time.Time) error {
	caCert, err := ParseCert(caCertPEM)
	if err != nil {
		return errors.Annotate(err, "cannot parse CA certificate")
	}
	srvCert, err := ParseCert(srvCertPEM)
	if err != nil {
		return errors.Annotate(err, "cannot parse server certificate")
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	opts := x509.VerifyOptions{
		DNSName:     "anyServer",
		Roots:       pool,
		CurrentTime: when,
	}
	_, err = srvCert.Verify(opts)
	return err
}

// verifyCertCA ensures that the given certificate is valid with respect
// to the given CA certificate at the given time.
func verifyCertCA(cert, caCert *x509.Certificate, when time.Time) error {
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	opts := x509.VerifyOptions{
		DNSName:     "anyServer",
		Roots:       pool,
		CurrentTime: when,
	}
	if _, err := cert.Verify(opts); err != nil {
		return errors.NewNotValid(err, "cert does not match CA cert")
	}
	return nil
}
