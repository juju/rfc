// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package tls

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/juju/errors"
)

// Config is the configuration to use for a TLS connection.
type Config struct {
	RawCert

	// ServerName is the name to expect on the remote server's cert.
	// Using "anything" will work but less securely.
	ServerName string

	// ExpectedServerCertPEM is the TLS certificate that the server must
	// use when the client connects.
	//
	// TODO(axw) this is nonsense, the client should not know the certificate
	// of the server up front, it just needs to be able to validate it.
	ExpectedServerCertPEM string
}

// ExpectedServerCert returns the TLS certificate that the server must
// use when the client connects.
func (cfg Config) ExpectedServerCert() (*x509.Certificate, error) {
	cert, err := ParseCert(cfg.ExpectedServerCertPEM)
	return cert, errors.Trace(err)
}

// TLS returns the raw tls.Config that corresponds with this config.
func (cfg Config) TLS() (*tls.Config, error) {
	tlsConfig := SecureTLSConfig()

	serverCert, err := cfg.ExpectedServerCert()
	if err != nil {
		return nil, errors.Trace(err)
	}

	serverName := cfg.ServerName
	if serverName == "" {
		if len(serverCert.DNSNames) == 0 {
			// We're letting this go for now.
			// TODO(ericsnow) fix this
			//return nil, errors.New("empty ServerName")
			serverName = "anything"
		} else {
			serverName = serverCert.DNSNames[0]
		}
	}
	tlsConfig.ServerName = serverName

	if cfg.CACertPEM != "" {
		// TODO(axw) CACertPEM should be required.
		caCert, err := cfg.CACert()
		if err != nil {
			return nil, errors.Trace(err)
		}
		pool := x509.NewCertPool()
		pool.AddCert(caCert)
		tlsConfig.RootCAs = pool
	}

	cert, err := cfg.Cert()
	if err != nil {
		return nil, errors.Trace(err)
	}
	tlsConfig.Certificates = []tls.Certificate{cert}

	tlsConfig.BuildNameToCertificate()

	return tlsConfig, nil
}

// Validate ensures that the config is correct.
func (cfg Config) Validate() error {
	if err := cfg.RawCert.Validate(); err != nil {
		return errors.Trace(err)
	}

	// Check the server cert.
	if cfg.ExpectedServerCertPEM != "" {
		xCert, err := cfg.ExpectedServerCert()
		if err != nil {
			return errors.NewNotValid(err, "invalid ExpectedServerCertPEM")
		}

		if cfg.ServerName == "" {
			if len(xCert.DNSNames) == 0 {
				// We're letting this go for now.
				// TODO(ericsnow) fix this
				//return errors.NewNotValid(nil, "ExpectedServerCertPEM missing server name")
			} else if len(xCert.DNSNames) > 1 {
				return errors.NewNotValid(nil, "ExpectedServerCertPEM has too many server names set")
			}
		}
	} else if cfg.ServerName == "" {
		return errors.NewNotValid(nil, "empty ServerName")
	}

	return nil
}

// knownGoodCipherSuites contains the list of secure cipher suites to use
// with tls.Config.  This list currently differs from the list in crypto/tls by
// excluding all RC4 implementations, due to known security vulnerabilities in
// RC4 - CVE-2013-2566, CVE-2015-2808.  We also exclude ciphersuites which do
// not provide forward secrecy.
var knownGoodCipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
}

// SecureTLSConfig returns a tls.Config that conforms to Juju's security
// standards, so as to avoid known security vulnerabilities in certain
// configurations.
//
// Currently it excludes RC4 implementations from the available ciphersuites,
// requires ciphersuites that provide forward secrecy, and sets the minimum TLS
// version to 1.2.
func SecureTLSConfig() *tls.Config {
	return &tls.Config{
		CipherSuites: knownGoodCipherSuites,
		MinVersion:   tls.VersionTLS12,
	}
}
