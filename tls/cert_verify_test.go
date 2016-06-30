// Copyright 2016 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package tls_test

import (
	"time"

	"github.com/juju/testing"
	jc "github.com/juju/testing/checkers"
	gc "gopkg.in/check.v1"

	"github.com/juju/rfc/tls"
)

type UtilsSuite struct {
	testing.IsolationSuite
}

var _ = gc.Suite(UtilsSuite{})

func (UtilsSuite) TestVerify(c *gc.C) {
	now := time.Now()
	caCert, caKey, err := tls.NewCA("foo", "1", now.Add(1*time.Minute), -1)
	c.Assert(err, jc.ErrorIsNil)

	var noHostnames []string
	srvCert, _, err := tls.NewServer(caCert, caKey, now.Add(3*time.Minute), noHostnames, -1)
	c.Assert(err, jc.ErrorIsNil)

	err = tls.Verify(srvCert, caCert, now)
	c.Assert(err, jc.ErrorIsNil)

	err = tls.Verify(srvCert, caCert, now.Add(55*time.Second))
	c.Assert(err, jc.ErrorIsNil)

	err = tls.Verify(srvCert, caCert, now.AddDate(0, 0, -8))
	c.Check(err, gc.ErrorMatches, "x509: certificate has expired or is not yet valid")

	err = tls.Verify(srvCert, caCert, now.Add(2*time.Minute))
	c.Check(err, gc.ErrorMatches, "x509: certificate has expired or is not yet valid")

	caCert2, caKey2, err := tls.NewCA("bar", "1", now.Add(1*time.Minute), -1)
	c.Assert(err, jc.ErrorIsNil)

	// Check original server certificate against wrong CA.
	err = tls.Verify(srvCert, caCert2, now)
	c.Check(err, gc.ErrorMatches, "x509: certificate signed by unknown authority")

	srvCert2, _, err := tls.NewServer(caCert2, caKey2, now.Add(1*time.Minute), noHostnames, -1)
	c.Assert(err, jc.ErrorIsNil)

	// Check new server certificate against original CA.
	err = tls.Verify(srvCert2, caCert, now)
	c.Check(err, gc.ErrorMatches, "x509: certificate signed by unknown authority")
}
