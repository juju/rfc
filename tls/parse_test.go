// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package tls_test

import (
	"github.com/juju/testing"
	jc "github.com/juju/testing/checkers"
	gc "gopkg.in/check.v1"

	"github.com/juju/rfc/tls"
)

type ParseSuite struct {
	testing.IsolationSuite
}

var _ = gc.Suite(ParseSuite{})

func (ParseSuite) TestParseCertificateValidCert(c *gc.C) {
	xCert, err := tls.ParseCert(caCertPEM)
	c.Assert(err, jc.ErrorIsNil)

	c.Check(xCert.Subject.CommonName, gc.Equals, "juju testing")
}

func (ParseSuite) TestParseCertificateMissingCert(c *gc.C) {
	_, err := tls.ParseCert(caKeyPEM)

	c.Check(err, gc.ErrorMatches, "no certificates found")
}

func (ParseSuite) TestParseCertificateInvalidCert(c *gc.C) {
	_, err := tls.ParseCert("hello")

	c.Check(err, gc.ErrorMatches, "no certificates found")
}
