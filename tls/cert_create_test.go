// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

package tls_test

import (
	"bytes"
	"crypto/rsa"
	stdtls "crypto/tls"
	"crypto/x509"
	"io"
	"io/ioutil"
	"net"
	"strings"
	"time"

	"github.com/juju/testing"
	jc "github.com/juju/testing/checkers"
	"github.com/juju/utils"
	gc "gopkg.in/check.v1"

	"github.com/juju/rfc/tls"
)

type CreateSuite struct {
	testing.IsolationSuite
}

var _ = gc.Suite(CreateSuite{})

func checkNotBefore(c *gc.C, cert *x509.Certificate, now time.Time) {
	// Check that the certificate is valid from one week before today.
	c.Check(cert.NotBefore.Before(now), jc.IsTrue)
	c.Check(cert.NotBefore.Before(now.AddDate(0, 0, -6)), jc.IsTrue)
	c.Check(cert.NotBefore.After(now.AddDate(0, 0, -8)), jc.IsTrue)
}

func checkNotAfter(c *gc.C, cert *x509.Certificate, expiry time.Time) {
	// Check the surrounding day.
	c.Assert(cert.NotAfter.Before(expiry.AddDate(0, 0, 1)), jc.IsTrue)
	c.Assert(cert.NotAfter.After(expiry.AddDate(0, 0, -1)), jc.IsTrue)
}

func (CreateSuite) TestParseCertificate(c *gc.C) {
	xcert, err := tls.ParseCert(caCertPEM)
	c.Assert(err, jc.ErrorIsNil)
	c.Assert(xcert.Subject.CommonName, gc.Equals, "juju testing")

	xcert, err = tls.ParseCert(caKeyPEM)
	c.Check(xcert, gc.IsNil)
	c.Assert(err, gc.ErrorMatches, "no certificates found")

	xcert, err = tls.ParseCert("hello")
	c.Check(xcert, gc.IsNil)
	c.Assert(err, gc.ErrorMatches, "no certificates found")
}

func (CreateSuite) TestParseCertAndKey(c *gc.C) {
	xcert, key, err := tls.ParseCertAndKey(caCertPEM, caKeyPEM)
	c.Assert(err, jc.ErrorIsNil)
	c.Assert(xcert.Subject.CommonName, gc.Equals, "juju testing")
	c.Assert(key, gc.NotNil)

	c.Assert(xcert.PublicKey.(*rsa.PublicKey), gc.DeepEquals, &key.PublicKey)
}

func (CreateSuite) TestNewServer(c *gc.C) {
	now := time.Now()
	expiry := roundTime(now.AddDate(1, 0, 0))
	caCertPEM, caKeyPEM, err := tls.NewCA("foo", "1", expiry, -1)
	c.Assert(err, jc.ErrorIsNil)

	caCert, _, err := tls.ParseCertAndKey(caCertPEM, caKeyPEM)
	c.Assert(err, jc.ErrorIsNil)

	srvCertPEM, srvKeyPEM, err := tls.NewServer(caCertPEM, caKeyPEM, expiry, nil, -1)
	c.Assert(err, jc.ErrorIsNil)
	checkCertificate(c, caCert, srvCertPEM, srvKeyPEM, now, expiry)
}

func (CreateSuite) TestNewDefaultServer(c *gc.C) {
	now := time.Now()
	expiry := roundTime(now.AddDate(1, 0, 0))
	caCertPEM, caKeyPEM, err := tls.NewCA("foo", "1", expiry, -1)
	c.Assert(err, jc.ErrorIsNil)

	caCert, _, err := tls.ParseCertAndKey(caCertPEM, caKeyPEM)
	c.Assert(err, jc.ErrorIsNil)

	srvCertPEM, srvKeyPEM, err := tls.NewDefaultServer(caCertPEM, caKeyPEM, nil, -1)
	c.Assert(err, jc.ErrorIsNil)
	srvCertExpiry := roundTime(time.Now().AddDate(10, 0, 0))
	checkCertificate(c, caCert, srvCertPEM, srvKeyPEM, now, srvCertExpiry)
}

func checkCertificate(c *gc.C, caCert *x509.Certificate, srvCertPEM, srvKeyPEM string, now, expiry time.Time) {
	srvCert, srvKey, err := tls.ParseCertAndKey(srvCertPEM, srvKeyPEM)
	c.Assert(err, jc.ErrorIsNil)
	c.Assert(srvCert.Subject.CommonName, gc.Equals, "*")
	checkNotBefore(c, srvCert, now)
	checkNotAfter(c, srvCert, expiry)
	c.Assert(srvCert.BasicConstraintsValid, jc.IsFalse)
	c.Assert(srvCert.IsCA, jc.IsFalse)
	c.Assert(srvCert.ExtKeyUsage, gc.DeepEquals, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})

	checkTLSConnection(c, caCert, srvCert, srvKey)
}

func (CreateSuite) TestNewServerHostnames(c *gc.C) {
	type test struct {
		hostnames           []string
		expectedDNSNames    []string
		expectedIPAddresses []net.IP
	}
	tests := []test{{
		[]string{},
		nil,
		nil,
	}, {
		[]string{"example.com"},
		[]string{"example.com"},
		nil,
	}, {
		[]string{"example.com", "127.0.0.1"},
		[]string{"example.com"},
		[]net.IP{net.IPv4(127, 0, 0, 1).To4()},
	}, {
		[]string{"::1"},
		nil,
		[]net.IP{net.IPv6loopback},
	}}
	for i, t := range tests {
		c.Logf("test %d: %v", i, t.hostnames)
		expiry := roundTime(time.Now().AddDate(1, 0, 0))
		srvCertPEM, srvKeyPEM, err := tls.NewServer(caCertPEM, caKeyPEM, expiry, t.hostnames, -1)
		c.Assert(err, jc.ErrorIsNil)
		srvCert, _, err := tls.ParseCertAndKey(srvCertPEM, srvKeyPEM)
		c.Assert(err, jc.ErrorIsNil)
		c.Assert(srvCert.DNSNames, gc.DeepEquals, t.expectedDNSNames)
		c.Assert(srvCert.IPAddresses, gc.DeepEquals, t.expectedIPAddresses)
	}
}

func (CreateSuite) TestWithNonUTCExpiry(c *gc.C) {
	expiry, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", "2012-11-28 15:53:57 +0100 CET")
	c.Assert(err, jc.ErrorIsNil)
	certPEM, keyPEM, err := tls.NewCA("foo", "1", expiry, -1)
	xcert, err := tls.ParseCert(certPEM)
	c.Assert(err, jc.ErrorIsNil)
	checkNotAfter(c, xcert, expiry)

	var noHostnames []string
	certPEM, _, err = tls.NewServer(certPEM, keyPEM, expiry, noHostnames, -1)
	xcert, err = tls.ParseCert(certPEM)
	c.Assert(err, jc.ErrorIsNil)
	checkNotAfter(c, xcert, expiry)
}

func (CreateSuite) TestNewServerWithInvalidCert(c *gc.C) {
	var noHostnames []string
	srvCert, srvKey, err := tls.NewServer(nonCACert, nonCAKey, time.Now(), noHostnames, -1)
	c.Check(srvCert, gc.Equals, "")
	c.Check(srvKey, gc.Equals, "")
	c.Assert(err, gc.ErrorMatches, "CA certificate is not a valid CA")
}

func (CreateSuite) TestVerify(c *gc.C) {
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

// checkTLSConnection checks that we can correctly perform a TLS
// handshake using the given credentials.
func checkTLSConnection(c *gc.C, caCert, srvCert *x509.Certificate, srvKey *rsa.PrivateKey) (caName string) {
	clientCertPool := x509.NewCertPool()
	clientCertPool.AddCert(caCert)

	var outBytes bytes.Buffer

	const msg = "hello to the server"
	p0, p1 := net.Pipe()
	p0 = &recordingConn{
		Conn:   p0,
		Writer: io.MultiWriter(p0, &outBytes),
	}

	var clientState stdtls.ConnectionState
	done := make(chan error)
	go func() {
		config := utils.SecureTLSConfig()
		config.Certificates = []stdtls.Certificate{{
			Certificate: [][]byte{srvCert.Raw},
			PrivateKey:  srvKey,
		}}

		conn := stdtls.Server(p1, config)
		defer conn.Close()
		data, err := ioutil.ReadAll(conn)
		c.Assert(err, jc.ErrorIsNil)
		c.Assert(string(data), gc.Equals, msg)
		close(done)
	}()

	tlsConfig := utils.SecureTLSConfig()
	tlsConfig.ServerName = "anyServer"
	tlsConfig.RootCAs = clientCertPool
	clientConn := stdtls.Client(p0, tlsConfig)
	defer clientConn.Close()

	_, err := clientConn.Write([]byte(msg))
	c.Assert(err, jc.ErrorIsNil)
	clientState = clientConn.ConnectionState()
	clientConn.Close()

	// wait for server to exit
	<-done

	outData := outBytes.String()
	c.Assert(outData, gc.Not(gc.HasLen), 0)
	if strings.Index(outData, msg) != -1 {
		c.Fatalf("TLS connection not encrypted")
	}
	c.Assert(clientState.VerifiedChains, gc.HasLen, 1)
	c.Assert(clientState.VerifiedChains[0], gc.HasLen, 2)
	return clientState.VerifiedChains[0][1].Subject.CommonName
}

type recordingConn struct {
	net.Conn
	io.Writer
}

func (c recordingConn) Write(buf []byte) (int, error) {
	return c.Writer.Write(buf)
}

// roundTime returns t rounded to the previous whole second.
func roundTime(t time.Time) time.Time {
	return t.Add(time.Duration(-t.Nanosecond()))
}

var (
	caCertPEM = `
-----BEGIN CERTIFICATE-----
MIIBnTCCAUmgAwIBAgIBADALBgkqhkiG9w0BAQUwJjENMAsGA1UEChMEanVqdTEV
MBMGA1UEAxMManVqdSB0ZXN0aW5nMB4XDTEyMTExNDE0Mzg1NFoXDTIyMTExNDE0
NDM1NFowJjENMAsGA1UEChMEanVqdTEVMBMGA1UEAxMManVqdSB0ZXN0aW5nMFow
CwYJKoZIhvcNAQEBA0sAMEgCQQCCOOpn9aWKcKr2GQGtygwD7PdfNe1I9BYiPAqa
2I33F5+6PqFdfujUKvoyTJI6XG4Qo/CECaaN9smhyq9DxzMhAgMBAAGjZjBkMA4G
A1UdDwEB/wQEAwIABDASBgNVHRMBAf8ECDAGAQH/AgEBMB0GA1UdDgQWBBQQDswP
FQGeGMeTzPbHW62EZbbTJzAfBgNVHSMEGDAWgBQQDswPFQGeGMeTzPbHW62EZbbT
JzALBgkqhkiG9w0BAQUDQQAqZzN0DqUyEfR8zIanozyD2pp10m9le+ODaKZDDNfH
8cB2x26F1iZ8ccq5IC2LtQf1IKJnpTcYlLuDvW6yB96g
-----END CERTIFICATE-----
`

	caKeyPEM = `
-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBAII46mf1pYpwqvYZAa3KDAPs91817Uj0FiI8CprYjfcXn7o+oV1+
6NQq+jJMkjpcbhCj8IQJpo32yaHKr0PHMyECAwEAAQJAYctedh4raLE+Ir0a3qnK
pjQSfiUggtYTvTf7+tfAnZu946PX88ysr7XHPkXEGP4tWDTbl8BfGndrTKswVOx6
RQIhAOT5OzafJneDQ5cuGLN/hxIPBLWxKT1/25O6dhtBlRyPAiEAkZfFvCtBZyKB
JFwDdp+7gE98mXtaFrjctLWeFx797U8CIAnnqiMTwWM8H2ljyhfBtYMXeTmu3zzU
0hfS4hcNwDiLAiEAkNXXU7YEPkFJD46ps1x7/s0UOutHV8tXZD44ou+l1GkCIQDO
HOzuvYngJpoClGw0ipzJPoNZ2Z/GkdOWGByPeKu/8g==
-----END RSA PRIVATE KEY-----
`

	nonCACert = `-----BEGIN CERTIFICATE-----
MIIBmjCCAUagAwIBAgIBADALBgkqhkiG9w0BAQUwJjENMAsGA1UEChMEanVqdTEV
MBMGA1UEAxMManVqdSB0ZXN0aW5nMB4XDTEyMTExNDE3MTU1NloXDTIyMTExNDE3
MjA1NlowJjENMAsGA1UEChMEanVqdTEVMBMGA1UEAxMManVqdSB0ZXN0aW5nMFow
CwYJKoZIhvcNAQEBA0sAMEgCQQC96/CsTTY1Va8et6QYNXwrssAi36asFlV/fksG
hqRucidiz/+xHvhs9EiqEu7NGxeVAkcfIhXu6/BDlobtj2v5AgMBAAGjYzBhMA4G
A1UdDwEB/wQEAwIABDAPBgNVHRMBAf8EBTADAgEBMB0GA1UdDgQWBBRqbxkIW4R0
vmmkUoYuWg9sDob4jzAfBgNVHSMEGDAWgBRqbxkIW4R0vmmkUoYuWg9sDob4jzAL
BgkqhkiG9w0BAQUDQQC3+KN8RppKdvlbP6fDwRC22PaCxd0PVyIHsn7I4jgpBPf8
Z3codMYYA5/f0AmUsD7wi7nnJVPPLZK7JWu4VI/w
-----END CERTIFICATE-----
`

	nonCAKey = `-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAL3r8KxNNjVVrx63pBg1fCuywCLfpqwWVX9+SwaGpG5yJ2LP/7Ee
+Gz0SKoS7s0bF5UCRx8iFe7r8EOWhu2Pa/kCAwEAAQJAdzuAxStUNPeuEWLJKkmp
wuVdqocuZCtBUeE/yMEOyibZ9NLKSuDJuDorkoeoiBz2vyUITHkLp4jgNmCI8NGg
AQIhAPZG9+3OghlzcqWR4nTho8KO/CuO9bu5G4jNEdIrSJ6BAiEAxWtoLZNMwI4Q
kj2moFk9GdBXZV9I0t1VTwcDvVyeAXkCIDrfvldQPdO9wJOKK3vLkS1qpyf2lhIZ
b1alx3PZuxOBAiAthPltYMRWtar+fTaZTFo5RH+SQSkibaRI534mQF+ySQIhAIml
yiWVLC2XrtwijDu1fwh/wtFCb/bPvqvgG5wgAO+2
-----END RSA PRIVATE KEY-----
`
)
