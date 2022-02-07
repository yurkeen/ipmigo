package ipmigo

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

const (
	openSessionRequestSize  = 32
	openSessionResponseSize = 36
	rakpMessage1Size        = 44
	rakpMessage2Size        = 40
	rakpMessage3Size        = 8
	rakpMessage4Size        = 8

	integrityCheckSize = 12        // Supported HMAC-SHA1-96 only (Section 13.28.1)
	authCodeSize       = sha1.Size // Supported RAKP-HMAC-SHA1 only (Section 13.28.1)
	sikSize            = sha1.Size
)

var (
	const1 = [sikSize]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	const2 = [sikSize]byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}
)

// Authentication Algorithm (Section 13.28)
type authAlgorithm uint8

const (
	authRakpNone authAlgorithm = iota
	authRakpHmacSHA1
	authRakpHmacMD5
	authRakpHmacSHA256
)

func (a authAlgorithm) String() string {
	switch a {
	case authRakpNone:
		return "RAKP-none"
	case authRakpHmacSHA1:
		return "RAKP-HMAC-SHA1"
	case authRakpHmacMD5:
		return "RAKP-HMAC-MD5"
	case authRakpHmacSHA256:
		return "RAKP-HMAC-SHA256"
	default:
		return fmt.Sprintf("%d (unknown)", a)
	}
}

// Integrity Algorithm (Section 13.28.4)
type integrityAlgorithm uint8

const (
	integrityNone integrityAlgorithm = iota
	integrityHmacSHA1_96
	integrityHmacMD5_128
	integrityMD5_128
	integrityHmacSHA256_128
)

func (a integrityAlgorithm) String() string {
	switch a {
	case integrityNone:
		return "None"
	case integrityHmacSHA1_96:
		return "HMAC-SHA1-96"
	case integrityHmacMD5_128:
		return "HMAC-MD5-128"
	case integrityMD5_128:
		return "MD5-128"
	case integrityHmacSHA256_128:
		return "HMAC-SHA256-128"
	default:
		return fmt.Sprintf("%d (unknown)", a)
	}
}

// Confidentiality Algorithm (Section 13.28.5)
type cryptAlgorithm uint8

const (
	cryptNone cryptAlgorithm = iota
	cryptAesCBC_128
	cryptXRC4_128
	cryptXRC4_40
)

func (a cryptAlgorithm) String() string {
	switch a {
	case cryptNone:
		return "None"
	case cryptAesCBC_128:
		return "AES-CBC-128"
	case cryptXRC4_128:
		return "xRC4-128"
	case cryptXRC4_40:
		return "xRC4-128"
	default:
		return fmt.Sprintf("%d (unknown)", a)
	}
}

// Cipher Suite (Section 22.15.2)
type cipherSuite struct {
	Auth      authAlgorithm
	Integrity integrityAlgorithm
	Crypt     cryptAlgorithm
}

func (c *cipherSuite) Equal(o *cipherSuite) bool {
	return c.Auth == o.Auth && c.Integrity == o.Integrity && c.Crypt == o.Crypt
}

func (c *cipherSuite) String() string {
	return fmt.Sprintf(`{"Auth":"%s","Integrity":"%s","Crypt":"%s"}`,
		c.Auth, c.Integrity, c.Crypt)
}

// Cipher Suite IDs (Table 22-20)
type CipherSuiteID uint

var unsupportedCipher = cipherSuite{0xff, 0xff, 0xff}

func (id CipherSuiteID) cipherSuite() cipherSuite {
	// Cipher Suite IDs (Table 22-20)
	csIds := []cipherSuite{
		{authRakpNone, integrityNone, cryptNone},                       // 0
		{authRakpHmacSHA1, integrityNone, cryptNone},                   // 1
		{authRakpHmacSHA1, integrityHmacSHA1_96, cryptNone},            // 2
		{authRakpHmacSHA1, integrityHmacSHA1_96, cryptAesCBC_128},      // 3
		{authRakpHmacSHA1, integrityHmacSHA1_96, cryptXRC4_128},        // 4
		{authRakpHmacSHA1, integrityHmacSHA1_96, cryptXRC4_40},         // 5
		{authRakpHmacMD5, integrityNone, cryptNone},                    // 6
		{authRakpHmacMD5, integrityHmacMD5_128, cryptNone},             // 7
		{authRakpHmacMD5, integrityHmacMD5_128, cryptAesCBC_128},       // 8
		{authRakpHmacMD5, integrityHmacMD5_128, cryptXRC4_128},         // 9
		{authRakpHmacMD5, integrityHmacMD5_128, cryptXRC4_40},          // 10
		{authRakpHmacMD5, integrityMD5_128, cryptNone},                 // 11
		{authRakpHmacMD5, integrityMD5_128, cryptAesCBC_128},           // 12
		{authRakpHmacMD5, integrityMD5_128, cryptXRC4_128},             // 13
		{authRakpHmacMD5, integrityMD5_128, cryptXRC4_40},              // 14
		{authRakpHmacSHA256, integrityNone, cryptNone},                 // 15
		{authRakpHmacSHA256, integrityHmacSHA256_128, cryptNone},       // 16
		{authRakpHmacSHA256, integrityHmacSHA256_128, cryptAesCBC_128}, // 17
		{authRakpHmacSHA256, integrityHmacSHA256_128, cryptXRC4_128},   // 18
		{authRakpHmacSHA256, integrityHmacSHA256_128, cryptXRC4_40},    // 19
	}
	if int(id) > len(csIds)-1 {
		return unsupportedCipher // Unsupported cipher suite.
	}
	return csIds[id]
}

// RMCP+ Open Session Request (Section 13.17)
type openSessionRequest struct {
	MessageTag     uint8
	ConsoleID      uint32 // Remote console session ID
	PrivilegeLevel PrivilegeLevel
	CipherSuiteID  CipherSuiteID
}

func (req *openSessionRequest) Marshal() ([]byte, error) {
	cipher := req.CipherSuiteID.cipherSuite()

	buf := make([]byte, openSessionRequestSize)
	buf[0] = req.MessageTag
	buf[1] = byte(req.PrivilegeLevel)
	//buf[2] = 0 // reserved
	//buf[3] = 0 // reserved

	// Our session ID
	binary.LittleEndian.PutUint32(buf[4:], req.ConsoleID)

	// Authentication payload
	buf[8] = 0 // authentication payload type(0)
	//buf[9] = 0  // reserved
	//buf[10] = 0 // reserved
	buf[11] = 8 // payload length(8)
	buf[12] = byte(cipher.Auth)
	//buf[13] = 0 // reserved
	//buf[14] = 0 // reserved
	//buf[15] = 0 // reserved

	// Integrity payload
	buf[16] = 1 // integrity payload type(1)
	//buf[17] = 0 // reserved
	//buf[18] = 0 // reserved
	buf[19] = 8 // payload length(8)
	buf[20] = byte(cipher.Integrity)
	//buf[21] = 0 // reserved
	//buf[22] = 0 // reserved
	//buf[23] = 0 // reserved

	// Confidentiality payload
	buf[24] = 2 // confidentiality payload type(2)
	//buf[25] = 0 // reserved
	//buf[26] = 0 // reserved
	buf[27] = 8 // payload length(8)
	buf[28] = byte(cipher.Crypt)
	//buf[29] = 0 // reserved
	//buf[30] = 0 // reserved
	//buf[31] = 0 // reserved

	return buf, nil
}

func (req *openSessionRequest) String() string {
	return fmt.Sprintf(
		`{"MessageTag":%d,"ConsoleID":%d,"PrivilegeLevel":"%s","CipherSuiteID":%d}`,
		req.MessageTag, req.ConsoleID, req.PrivilegeLevel, req.CipherSuiteID)
}

// RMCP+ and RAKP Message Status Code (Section13.24)
type rakpStatusCode uint8

const (
	rakpStatusNoErrors rakpStatusCode = iota
	rakpStatusInsufficientResource
	rakpStatusInvalidSessionID
	rakpStatusInvalidPayloadType
	rakpStatusInvalidAuthAlgorithm
	rakpStatusInvalidIntegrityAlgorithm
	rakpStatusNoMatchingAuthPayload
	rakpStatusNoMatchingIntegrityPayload
	rakpStatusInactiveSessionID
	rakpStatusInvalidRole
	rakpStatusUnauthorizedRoleRequested
	rakpStatusInsufficientResources
	rakpStatusInvalidNameLength
	rakpStatusUnauthorizedName
	rakpStatusUnauthorizedGUID
	rakpStatusInvalidIntegrityCheck
	rakpStatusInvalidConfidentialityAlgorithm
	rakpStatusNoCipherSuiteMatch
	rakpStatusIllegalParameter
)

func (c rakpStatusCode) String() string {
	switch c {
	case rakpStatusNoErrors:
		return "No errors"
	case rakpStatusInsufficientResource:
		return "Insufficient resources to create a session"
	case rakpStatusInvalidSessionID:
		return "Invalid Session ID"
	case rakpStatusInvalidPayloadType:
		return "Invalid payload type"
	case rakpStatusInvalidAuthAlgorithm:
		return "Invalid authentication algorithm"
	case rakpStatusInvalidIntegrityAlgorithm:
		return "Invalid integrity algorithm"
	case rakpStatusNoMatchingAuthPayload:
		return "No matching authentication payload"
	case rakpStatusNoMatchingIntegrityPayload:
		return "No matching integrity payload"
	case rakpStatusInactiveSessionID:
		return "Inactive Session ID"
	case rakpStatusInvalidRole:
		return "Invalid role"
	case rakpStatusUnauthorizedRoleRequested:
		return "Unauthorized role or privilege level requested"
	case rakpStatusInsufficientResources:
		return "Insufficient resources to create a session at the requested role"
	case rakpStatusInvalidNameLength:
		return "Invalid name length"
	case rakpStatusUnauthorizedName:
		return "Unauthorized name"
	case rakpStatusUnauthorizedGUID:
		return "Unauthorized GUID"
	case rakpStatusInvalidIntegrityCheck:
		return "Invalid integrity check value"
	case rakpStatusInvalidConfidentialityAlgorithm:
		return "Invalid confidentiality algorithm"
	case rakpStatusNoCipherSuiteMatch:
		return "No Cipher Suite match with proposed security algorithms"
	case rakpStatusIllegalParameter:
		return "Illegal or unrecognized parameter"
	default:
		return fmt.Sprintf("Unknown(%d)", c)
	}
}

// RMCP+ Open Session Response (Section 13.18)
type openSessionResponse struct {
	MessageTag     uint8
	StatusCode     rakpStatusCode
	PrivilegeLevel PrivilegeLevel
	ConsoleID      uint32 // Remote console session ID
	ManagedID      uint32 // Managed system session ID
	CipherSuite    cipherSuite
}

func (resp *openSessionResponse) Unmarshal(buf []byte) ([]byte, error) {
	if l := len(buf); l < openSessionResponseSize {
		buf = append(buf, make([]byte, openSessionResponseSize-l)...)
	}

	resp.MessageTag = buf[0]
	resp.StatusCode = rakpStatusCode(buf[1])
	resp.PrivilegeLevel = PrivilegeLevel(buf[2])
	resp.ConsoleID = binary.LittleEndian.Uint32(buf[4:])
	resp.ManagedID = binary.LittleEndian.Uint32(buf[8:])
	resp.CipherSuite.Auth = authAlgorithm(buf[16])
	resp.CipherSuite.Integrity = integrityAlgorithm(buf[24])
	resp.CipherSuite.Crypt = cryptAlgorithm(buf[32])
	return buf[openSessionResponseSize:], nil
}

func (resp *openSessionResponse) String() string {
	return fmt.Sprintf(
		`{"MessageTag":%d,"StatusCode":"%s","PrivilegeLevel":"%s","ConsoleID":%d,"ManagedID":%d,"CipherSuite":%s}`,
		resp.MessageTag, resp.StatusCode, resp.PrivilegeLevel, resp.ConsoleID, resp.ManagedID, &resp.CipherSuite,
	)
}

// RAKP Message 1 (Section 13.20)
type rakpMessage1 struct {
	MessageTag      uint8
	ManagedID       uint32    // Managed system sesssion ID
	ConsoleRand     [16]uint8 // Remote console random number
	PrivilegeLevel  PrivilegeLevel
	PrivilegeLookup bool // Use username and privilege for lookup
	Username        string
}

func (m *rakpMessage1) RequestedRole() byte {
	b := byte(m.PrivilegeLevel)
	if !m.PrivilegeLookup {
		b |= 0x10
	}
	return b
}

func (m *rakpMessage1) Marshal() ([]byte, error) {
	buf := make([]byte, rakpMessage1Size)
	buf[0] = m.MessageTag
	// buf[1] = 0 // reserved
	// buf[2] = 0 // reserved
	// buf[3] = 0 // reserved
	binary.LittleEndian.PutUint32(buf[4:], m.ManagedID)

	// 16 byte random number
	if _, err := rand.Read(m.ConsoleRand[:]); err != nil {
		return nil, err
	}
	copy(buf[8:24], m.ConsoleRand[:])

	buf[24] = m.RequestedRole()
	// buf[25] = 0 // reserved
	// buf[26] = 0 // reserved

	// Username
	ulen := len(m.Username)
	buf[27] = byte(ulen)
	copy(buf[28:], m.Username)

	return buf[:28+ulen], nil
}

func (m *rakpMessage1) String() string {
	return fmt.Sprintf(
		`{"MessageTag":%d,"ManagedID":%d,"ConsoleRand":"%s","PrivilegeLevel":"%s","PrivilegeLookup":%t,"Username":"%s"}`,
		m.MessageTag, m.ManagedID, hex.EncodeToString(m.ConsoleRand[:]), m.PrivilegeLevel, m.PrivilegeLookup, m.Username,
	)
}

// RAKP Message 2 (Section 13.21)
type rakpMessage2 struct {
	MessageTag          uint8
	StatusCode          rakpStatusCode
	ConsoleID           uint32    // Remote console session ID
	ManagedRand         [16]uint8 // Managed system random number
	ManagedGUID         [16]uint8 // Managed system GUID
	KeyExchangeAuthCode [authCodeSize]byte
}

func (m2 *rakpMessage2) ValidateAuthCode(c *Config, m1 *rakpMessage1) error {
	if !requiredAuthentication(c.CipherSuiteID) {
		return nil
	}

	key := make([]byte, passwordMaxLengthV2_0)
	copy(key, c.Password)

	data := make([]byte, 58+len(m1.Username))
	binary.LittleEndian.PutUint32(data, m2.ConsoleID)     // SIDm
	binary.LittleEndian.PutUint32(data[4:], m1.ManagedID) // SIDc
	copy(data[8:], m1.ConsoleRand[:])                     // Rm
	copy(data[24:], m2.ManagedRand[:])                    // Rc
	copy(data[40:], m2.ManagedGUID[:])                    // GUIDc
	data[56] = m1.RequestedRole()                         // ROLEm
	data[57] = byte(len(m1.Username))                     // ULENGTHm
	copy(data[58:], m1.Username)                          // UNAMEm

	mac := hmac.New(sha1.New, key)
	mac.Write(data)

	if s := mac.Sum(nil); !hmac.Equal(m2.KeyExchangeAuthCode[:], s) {
		return fmt.Errorf(
			"invalid RAKP 2 HMAC: %s - %s",
			hex.EncodeToString(m2.KeyExchangeAuthCode[:]), hex.EncodeToString(s),
		)
	}
	return nil
}

func (m2 *rakpMessage2) Unmarshal(buf []byte) ([]byte, error) {
	if l := len(buf); l < rakpMessage2Size {
		buf = append(buf, make([]byte, rakpMessage2Size-l)...)
	}

	m2.MessageTag = buf[0]
	m2.StatusCode = rakpStatusCode(buf[1])
	m2.ConsoleID = binary.LittleEndian.Uint32(buf[4:])
	copy(m2.ManagedRand[:], buf[8:24])
	copy(m2.ManagedGUID[:], buf[24:40])
	copy(m2.KeyExchangeAuthCode[:], buf[40:])

	return buf[rakpMessage2Size:], nil
}

func (m2 *rakpMessage2) String() string {
	return fmt.Sprintf(
		`{"MessageTag":%d,"StatusCode":"%s","ConsoleID":%d,"ManagedRand":"%s","ManagedGUID":"%s","KeyExchangeAuthCode":"%s"}`,
		m2.MessageTag, m2.StatusCode, m2.ConsoleID,
		hex.EncodeToString(m2.ManagedRand[:]),
		hex.EncodeToString(m2.ManagedGUID[:]),
		hex.EncodeToString(m2.KeyExchangeAuthCode[:]),
	)
}

// RAKP Message 3 (Section 13.22)
type rakpMessage3 struct {
	MessageTag          uint8
	StatusCode          rakpStatusCode
	ManagedID           uint32
	KeyExchangeAuthCode [authCodeSize]byte

	SIK [sikSize]byte // Session Integrity Key
	K1  [sikSize]byte
	K2  [sikSize]byte
}

func (m3 *rakpMessage3) GenerateAuthCode(c *Config, m1 *rakpMessage1, m2 *rakpMessage2) {
	if !requiredAuthentication(c.CipherSuiteID) {
		return
	}

	key := make([]byte, passwordMaxLengthV2_0)
	copy(key, c.Password)

	data := make([]byte, 22+len(m1.Username))
	copy(data, m2.ManagedRand[:])                          // Rc
	binary.LittleEndian.PutUint32(data[16:], m2.ConsoleID) // SIDm
	data[20] = m1.RequestedRole()                          // ROLEm
	data[21] = byte(len(m1.Username))                      // ULENGTHm
	copy(data[22:], m1.Username)                           // UNAMEm

	mac := hmac.New(sha1.New, key)
	mac.Write(data)
	copy(m3.KeyExchangeAuthCode[:], mac.Sum(nil))
}

func (m3 *rakpMessage3) GenerateSIK(c *Config, m1 *rakpMessage1, m2 *rakpMessage2) {
	if !requiredAuthentication(c.CipherSuiteID) {
		return
	}

	// No KG key support
	key := make([]byte, passwordMaxLengthV2_0)
	copy(key, c.Password)

	data := make([]byte, 34+len(m1.Username))
	copy(data, m1.ConsoleRand[:])      // Rm
	copy(data[16:], m2.ManagedRand[:]) // Rc
	data[32] = m1.RequestedRole()      // ROLEm
	data[33] = byte(len(m1.Username))  // ULENGTHm
	copy(data[34:], m1.Username)       // UNAMEm

	mac := hmac.New(sha1.New, key)
	mac.Write(data)
	copy(m3.SIK[:], mac.Sum(nil))
}

func (m3 *rakpMessage3) GenerateK1(c *Config) {
	if !requiredAuthentication(c.CipherSuiteID) {
		return
	}

	key := make([]byte, len(m3.SIK))
	copy(key, m3.SIK[:])

	mac := hmac.New(sha1.New, key)
	mac.Write(const1[:])
	copy(m3.K1[:], mac.Sum(nil))
}

func (m3 *rakpMessage3) GenerateK2(c *Config) {
	if !requiredAuthentication(c.CipherSuiteID) {
		return
	}

	key := make([]byte, len(m3.SIK))
	copy(key, m3.SIK[:])

	mac := hmac.New(sha1.New, key)
	mac.Write(const2[:])
	copy(m3.K2[:], mac.Sum(nil))
}

func (m3 *rakpMessage3) Marshal() ([]byte, error) {
	size := rakpMessage3Size + len(m3.KeyExchangeAuthCode)

	buf := make([]byte, size)
	buf[0] = m3.MessageTag
	buf[1] = byte(m3.StatusCode)
	// buf[2] = 0 // reserved
	// buf[3] = 0 // reserved
	binary.LittleEndian.PutUint32(buf[4:], m3.ManagedID)
	copy(buf[8:], m3.KeyExchangeAuthCode[:])

	return buf, nil
}

func (m3 *rakpMessage3) String() string {
	return fmt.Sprintf(
		`{"MessageTag":%d,"StatusCode":"%s","ManagedID":%d,"KeyExchangeAuthCode":"%s"}`,
		m3.MessageTag, m3.StatusCode, m3.ManagedID, hex.EncodeToString(m3.KeyExchangeAuthCode[:]))
}

type rakpMessage4 struct {
	MessageTag          uint8
	StatusCode          rakpStatusCode
	ConsoleID           uint32 // Remote console session ID
	IntegrityCheckValue [integrityCheckSize]byte
}

func (m4 *rakpMessage4) ValidateAuthCode(c *Config, m1 *rakpMessage1, m2 *rakpMessage2, m3 *rakpMessage3) error {
	if !requiredAuthentication(c.CipherSuiteID) {
		return nil
	}

	key := make([]byte, len(m3.SIK))
	copy(key, m3.SIK[:])

	data := make([]byte, 36)
	copy(data, m1.ConsoleRand[:])                          // Rm
	binary.LittleEndian.PutUint32(data[16:], m1.ManagedID) // SIDc
	copy(data[20:], m2.ManagedGUID[:])                     // GUIDc

	mac := hmac.New(sha1.New, key)
	mac.Write(data)
	if s := mac.Sum(nil)[:integrityCheckSize]; !hmac.Equal(m4.IntegrityCheckValue[:], s) {
		return fmt.Errorf(
			"invalid RAKP 4 HMAC: %s - %s",
			hex.EncodeToString(m4.IntegrityCheckValue[:]),
			hex.EncodeToString(s),
		)
	}
	return nil
}

func (m4 *rakpMessage4) Unmarshal(buf []byte) ([]byte, error) {
	size := rakpMessage4Size + len(m4.IntegrityCheckValue)
	if l := len(buf); l < size {
		buf = append(buf, make([]byte, size-l)...)
	}

	m4.MessageTag = buf[0]
	m4.StatusCode = rakpStatusCode(buf[1])
	m4.ConsoleID = binary.LittleEndian.Uint32(buf[4:])
	copy(m4.IntegrityCheckValue[:], buf[8:])

	return buf[size:], nil
}

func (r *rakpMessage4) String() string {
	return fmt.Sprintf(
		`{"MessageTag":%d,"StatusCode":"%s","ConsoleID":%d,"IntegrityCheckValue":"%s"}`,
		r.MessageTag, r.StatusCode, r.ConsoleID, hex.EncodeToString(r.IntegrityCheckValue[:]))
}

func requiredAuthentication(cid CipherSuiteID) bool {
	switch auth := cid.cipherSuite().Auth; auth {
	default:
		panic("Unsupported authentication algorithm: " + auth.String())
	case authRakpNone:
		return false
	case authRakpHmacSHA1:
		return true
	}
}

func requiredIntegrity(cid CipherSuiteID) bool {
	switch integrity := cid.cipherSuite().Integrity; integrity {
	default:
		panic("unsupported integrity algorithm: " + integrity.String())
	case integrityNone:
		return false
	case integrityHmacSHA1_96:
		return true
	}
}

func requiredConfidentiality(cid CipherSuiteID) bool {
	switch crypt := cid.cipherSuite().Crypt; crypt {
	case cryptNone:
		return false
	case cryptAesCBC_128:
		return true
	default:
		panic("unsupported confidentiality algorithm: " + crypt.String())
	}
}
