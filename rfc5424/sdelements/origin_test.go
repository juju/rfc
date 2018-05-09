package sdelements_test

import (
	"net"

	"github.com/juju/rfc/rfc5424"

	"github.com/juju/rfc/rfc5424/sdelements"
	"github.com/juju/testing"
	jc "github.com/juju/testing/checkers"
	"github.com/juju/version"
	gc "gopkg.in/check.v1"
)

type OriginSuite struct {
	testing.IsolationSuite
}

var _ = gc.Suite(&OriginSuite{})

var originSetup = sdelements.Origin{
	IPs: []net.IP{
		net.IPv4(1, 2, 3, 4),
	},
	EnterpriseID: sdelements.OriginEnterpriseID{
		Number:  32473,
		SubTree: []int{1, 2, 3, 4},
	},
	SoftwareName: "foo-bar",
	SoftwareVersion: version.Number{
		Major: 1,
		Minor: 2,
	},
}

func (s *OriginSuite) TestID(c *gc.C) {
	origin := sdelements.Origin{}
	c.Assert(origin.ID(), gc.Equals, rfc5424.StructuredDataName("origin"))
}

func (s *OriginSuite) TestParams(c *gc.C) {
	params := originSetup.Params()

	want := []rfc5424.StructuredDataParam{
		rfc5424.StructuredDataParam{
			Name:  "ip",
			Value: rfc5424.StructuredDataParamValue("1.2.3.4"),
		},
		rfc5424.StructuredDataParam{
			Name:  "enterpriseID",
			Value: rfc5424.StructuredDataParamValue("32473.4.3.2.1"),
		},
		rfc5424.StructuredDataParam{
			Name:  "software",
			Value: rfc5424.StructuredDataParamValue("foo-bar"),
		},
		rfc5424.StructuredDataParam{
			Name:  "swVersion",
			Value: rfc5424.StructuredDataParamValue("1.2.0"),
		},
	}

	c.Assert(params, gc.DeepEquals, want)
}

func (s *OriginSuite) TestValidate(c *gc.C) {
	err := originSetup.Validate()
	c.Assert(err, jc.ErrorIsNil)
}

func (s *OriginSuite) TestValidateEnterpriseIDError(c *gc.C) {
	origin := sdelements.Origin{
		SoftwareName: "foo-bar",
	}
	err := origin.Validate()
	c.Assert(err, gc.ErrorMatches, "empty EnterpriseID")
}

func (s *OriginSuite) TestValidateSoftwareNameError(c *gc.C) {
	origin := sdelements.Origin{
		EnterpriseID: sdelements.OriginEnterpriseID{
			Number:  32473,
			SubTree: []int{1, 2, 3, 4},
		},
	}
	err := origin.Validate()
	c.Assert(err, gc.ErrorMatches, "empty SoftwareName")
}

func (s *OriginSuite) TestValidateSoftwareNameMaxError(c *gc.C) {
	origin := sdelements.Origin{
		EnterpriseID: sdelements.OriginEnterpriseID{
			Number:  32473,
			SubTree: []int{1, 2, 3, 4},
		},
		SoftwareName: "foo-bar-software-name-that-is-to-big-and-break-this",
	}
	err := origin.Validate()
	c.Assert(err, gc.ErrorMatches, "SoftwareName too big \\(51 UTF-8 > 48 max\\)")
}

func (s *OriginSuite) TestValidateSoftwareVersionError(c *gc.C) {
	origin := sdelements.Origin{
		EnterpriseID: sdelements.OriginEnterpriseID{
			Number:  32473,
			SubTree: []int{1, 2, 3, 4},
		},
		SoftwareName: "foo-bar",
		SoftwareVersion: version.Number{
			Major: 999999999999,
			Tag:   "foo-bar-tag-lots-of-text-to-break-this",
		},
	}
	err := origin.Validate()
	c.Assert(err, gc.ErrorMatches, "SoftwareVersion too big \\(54 UTF-8 > 32 max\\)")
}
