// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package tlstest

import (
	"time"

	"github.com/juju/rfc/tls"
	"github.com/juju/rfc/tls/internal/cert"
)

func init() {
	if err := ServerCert.Validate(); err != nil {
		panic(err)
	}
}

var (
	CACert      = mustNewCA()
	ServerCert  = mustNewServer()
	OtherCACert = mustNewCA()
)

func mustNewCA() tls.RawCert {
	cert.KeyBits = 512
	caCert, caKey, err := cert.NewCA("juju testing", "1234-ABCD-IS-NOT-A-REAL-UUID", time.Now().AddDate(10, 0, 0))
	if err != nil {
		panic(err)
	}
	return tls.RawCert{
		CertPEM: string(caCert),
		KeyPEM:  string(caKey),
	}
}

func mustNewServer() tls.RawCert {
	cert.KeyBits = 512
	var hostnames []string
	srvCert, srvKey, err := cert.NewServer(CACert.CertPEM, CACert.KeyPEM, time.Now().AddDate(10, 0, 0), hostnames)
	if err != nil {
		panic(err)
	}
	return tls.RawCert{
		CertPEM:   string(srvCert),
		KeyPEM:    string(srvKey),
		CACertPEM: CACert.CertPEM,
	}
}
