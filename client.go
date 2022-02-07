package ipmigo

import (
	"fmt"
	"time"
)

type Version int

const (
	V1_5 Version = iota + 1
	V2_0
)

// Channel Privilege Levels. (Section 6.8)
type PrivilegeLevel uint8

const (
	// BMC will pick the Cipher Suite returned in the RMCP+ Open Session Response
	// by checking the algorithms proposed in the RMCP+ Open Session Request
	// against the Cipher Suites available for each privilege level, starting
	// with the “OEM Proprietary level” and progressing to lower privilege levels
	// until a match is found. The resultant match results in an ‘effective’
	// maximum privilege level for the session.
	RoleBMC PrivilegeLevel = iota
	RoleCallback
	RoleUser
	RoleOperator
	RoleAdministrator
	RoleOEM
)

func (p PrivilegeLevel) String() string {
	level := [6]string{
		RoleBMC:           "BMC_DEFINED",
		RoleCallback:      "CALLBACK",
		RoleUser:          "USER",
		RoleOperator:      "OPERATOR",
		RoleAdministrator: "ADMINISTRATOR",
		RoleOEM:           "OEM_DEFINED",
	}
	if int(p) > len(level)-1 {
		return "INVALID"
	}
	return level[p]
}

// Config holds IPMI Client configuraton options.
type Config struct {
	Version       Version        // IPMI version to use
	Network       string         // See net.Dial parameter (The default is `udp`)
	Address       string         // See net.Dial parameter
	Timeout       time.Duration  // Each connect/read-write timeout (The default is 5sec)
	Retries       uint           // Number of retries (The default is `0`)
	Username      string         // Remote server username
	Password      string         // Remote server password
	Role          PrivilegeLevel // Session privilege level (The default is `Administrator`)
	CipherSuiteID CipherSuiteID  // ID of cipher suite, See Table 22-20 (The default is `0` which no auth and no encrypt)

	// Workaround options

	// Will allow to get analog sensor readings of a discrete sensor
	// (For details, see to freeipmi's same name option)
	Discretereading bool
}

func (c *Config) setDefault() {
	if c.Version == 0 {
		c.Version = V2_0
	}
	if c.Network == "" {
		c.Network = "udp"
	}
	if c.Timeout == 0 {
		c.Timeout = 5 * time.Second
	}
	if c.Role == 0 {
		c.Role = RoleAdministrator
	}
}

func (c *Config) validate() error {
	switch c.Version {
	case V2_0:
		if l := len(c.Password); l > passwordMaxLengthV2_0 {
			return fmt.Errorf("password is longer than %d bytes - %d", passwordMaxLengthV2_0, l)
		}

		if c.CipherSuiteID.cipherSuite() == unsupportedCipher {
			return fmt.Errorf("invalid Cipher Suite ID - %d", c.CipherSuiteID)
		}
	case V1_5:
		// TODO Support v1.5 ?
		fallthrough
	default:
		return fmt.Errorf("unsupported IPMI version (%d)", c.Version)
	}

	if c.Role > RoleAdministrator {
		return fmt.Errorf("unsupported Privilege Level - %d", c.Role)
	}

	if len(c.Username) > userNameMaxLength {
		return fmt.Errorf("username is longer than %d bytes", userNameMaxLength)
	}

	return nil
}

// IPMI Client
type Client struct {
	session session
	config  *Config

	sdrReadingBytes uint8 // for GetSDRCommand(byte to read of each BMC)
}

func (c *Client) Ping() error               { return c.session.Ping() }
func (c *Client) Open() error               { return c.session.Open() }
func (c *Client) Close() error              { return c.session.Close() }
func (c *Client) Execute(cmd Command) error { return c.session.Execute(cmd) }

// Create an IPMI Client
func NewClient(c Config) (*Client, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	c.setDefault()

	var s session
	switch c.Version {
	case V1_5:
		s = newSessionV1_5(&c)
	case V2_0:
		s = newSessionV2_0(&c)
	}
	return &Client{session: s, config: &c, sdrReadingBytes: sdrDefaultReadBytes}, nil
}
