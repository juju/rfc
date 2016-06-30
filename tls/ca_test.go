// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package tls_test

import (
	"crypto/rsa"
	"time"

	"github.com/juju/testing"
	jc "github.com/juju/testing/checkers"
	gc "gopkg.in/check.v1"

	"github.com/juju/rfc/tls"
)

type CASuite struct {
	testing.IsolationSuite
}

var _ = gc.Suite(CASuite{})

func (CASuite) TestNewCA(c *gc.C) {
	now := time.Now()
	expiry := roundTime(now.AddDate(0, 0, 1))
	caCertPEM, caKeyPEM, err := tls.NewCA("foo", "1", expiry, -1)
	c.Assert(err, jc.ErrorIsNil)

	caCert, caKey, err := tls.ParseCertAndKey(caCertPEM, caKeyPEM)
	c.Assert(err, jc.ErrorIsNil)

	c.Check(caKey, gc.FitsTypeOf, (*rsa.PrivateKey)(nil))
	c.Check(caCert.Subject.CommonName, gc.Equals, `juju-generated CA for model "foo"`)
	checkNotBefore(c, caCert, now)
	checkNotAfter(c, caCert, expiry)
	c.Check(caCert.BasicConstraintsValid, jc.IsTrue)
	c.Check(caCert.IsCA, jc.IsTrue)
	//c.Assert(caCert.MaxPathLen, Equals, 0)	TODO it ends up as -1 - check that this is ok.
}
