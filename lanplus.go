package ipmigo

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
)

const (
	consoleID uint32 = 0x49504d49 // 'IPMI'

	sessionHeaderV2_0Size = 12 // When payload type is not OEM
)

type sessionHeaderV2_0 struct {
	authType      authType
	payloadType   payloadType
	id            uint32
	sequence      uint32
	payloadLength uint16
}

func (s *sessionHeaderV2_0) ID() uint32               { return s.id }
func (s *sessionHeaderV2_0) AuthType() authType       { return s.authType }
func (s *sessionHeaderV2_0) PayloadType() payloadType { return s.payloadType }
func (s *sessionHeaderV2_0) SetEncrypted(b bool)      { s.payloadType.SetEncrypted(b) }
func (s *sessionHeaderV2_0) SetAuthenticated(b bool)  { s.payloadType.SetAuthenticated(b) }
func (s *sessionHeaderV2_0) PayloadLength() int       { return int(s.payloadLength) }
func (s *sessionHeaderV2_0) SetPayloadLength(n int)   { s.payloadLength = uint16(n) }

func (s *sessionHeaderV2_0) Marshal() ([]byte, error) {
	buf := make([]byte, sessionHeaderV2_0Size)
	buf[0] = byte(s.authType)
	buf[1] = byte(s.payloadType)
	binary.LittleEndian.PutUint32(buf[2:], s.id)
	binary.LittleEndian.PutUint32(buf[6:], s.sequence)
	binary.LittleEndian.PutUint16(buf[10:], s.payloadLength)
	return buf, nil
}

func (s *sessionHeaderV2_0) Unmarshal(buf []byte) ([]byte, error) {
	if len(buf) < sessionHeaderV2_0Size {
		return nil, fmt.Errorf("incorrect IPMI 2.0 session header size: %d", len(buf))
	}
	s.authType = authType(buf[0])
	s.payloadType = payloadType(buf[1])
	s.id = binary.LittleEndian.Uint32(buf[2:])
	s.sequence = binary.LittleEndian.Uint32(buf[6:])
	s.payloadLength = binary.LittleEndian.Uint16(buf[10:])
	return buf[sessionHeaderV2_0Size:], nil
}

func (s *sessionHeaderV2_0) String() string {
	return fmt.Sprintf(`{"AuthType":"%s","PayLoadType":%d,"ID":%d,"Sequence":%d,"PayloadLength":%d}`,
		s.authType, s.payloadType, s.id, s.sequence, s.payloadLength)
}

type sessionV2_0 struct {
	conn     net.Conn
	config   *Config
	id       uint32 // Session ID
	sequence uint32 // Session Sequence Number
	rqSeq    uint8  // Command Sequence Number
	k1       []byte // Integrity Key
	k2       []byte // Cipher Key
}

func (s *sessionV2_0) ActiveSession() bool {
	return s.id > 0
}

func (s *sessionV2_0) Header(p payloadType) sessionHeader {
	return &sessionHeaderV2_0{
		authType:    authTypeRMCPPlus,
		id:          s.id,
		sequence:    s.NextSequence(),
		payloadType: p,
	}
}

func (s *sessionV2_0) Ping() error {
	conn, err := net.DialTimeout(s.config.Network, s.config.Address, s.config.Timeout)
	if err != nil {
		return err
	}
	defer conn.Close()

	return ping(conn, s.config.Timeout)
}

func (s *sessionV2_0) Open() error {
	if s.conn != nil {
		return nil
	}

	err := retry(int(s.config.Retries), func() error {
		conn, e := net.DialTimeout(s.config.Network, s.config.Address, s.config.Timeout)
		if e == nil {
			s.conn = conn
		}
		return e
	})
	if err != nil {
		return err
	}

	err = s.openSession()
	if err != nil {
		defer s.Close()
	}
	return err
}

func (s *sessionV2_0) openSession() error {
	// 1. Get Channel Authentication Capabilities

	// Send in 1.5 packet format to query any server
	s1 := &sessionV1_5{config: s.config, conn: s.conn}
	cac := newChannelAuthCapCommand(V2_0, s.config.Role)
	if _, err := s1.execute(cac); err != nil {
		// Retry, without requesting IPMI V2
		cac = newChannelAuthCapCommand(V1_5, s.config.Role)
		if _, err := s1.execute(cac); err != nil {
			return err
		}
	}

	if !cac.IsSupportedAuthType(authTypeRMCPPlus) {
		return errors.New("RMCP+ not supported")
	}

	// 2. Open Session Request
	var pkt *ipmiPacket
	err := retry(int(s.config.Retries), func() (e error) {
		req := &ipmiPacket{
			RMCPHeader:    newRMCPHeaderForIPMI(),
			SessionHeader: s.Header(payloadTypeRMCPOpenReq),
			Request: &openSessionRequest{
				ConsoleID:      consoleID,
				PrivilegeLevel: s.config.Role,
				CipherSuiteID:  s.config.CipherSuiteID,
			},
		}
		pkt, e = s.SendPacket(req)
		return
	})
	if err != nil {
		return err
	}

	osr, ok := pkt.Response.(*openSessionResponse)
	if !ok {
		return errors.New("unexpected response for open session received")
	}

	if osr.StatusCode != rakpStatusNoErrors {
		return fmt.Errorf("open session response indicated errors: %s", osr.StatusCode)
	}

	if consoleID != osr.ConsoleID {
		return fmt.Errorf("console session ID mismatch 0x%x - 0x%x", consoleID, osr.ConsoleID)
	}

	if reqSuite := s.config.CipherSuiteID.cipherSuite(); !reqSuite.Equal(&osr.CipherSuite) {
		return fmt.Errorf("cipher suite mismatch %s - %s", reqSuite, osr.CipherSuite)
	}

	// 3. Exchange information(RAKP Message 1,2)
	m1 := &rakpMessage1{
		ManagedID:       osr.ManagedID,
		PrivilegeLevel:  s.config.Role,
		PrivilegeLookup: false,
		Username:        s.config.Username,
	}

	err = retry(int(s.config.Retries), func() (e error) {
		req := &ipmiPacket{
			RMCPHeader:    newRMCPHeaderForIPMI(),
			SessionHeader: s.Header(payloadTypeRAKP1),
			Request:       m1,
		}
		pkt, e = s.SendPacket(req)
		return
	})
	if err != nil {
		return err
	}

	m2, ok := pkt.Response.(*rakpMessage2)
	if !ok {
		return errors.New("unexpected RAKP 2 response received")
	}

	if m2.StatusCode != rakpStatusNoErrors {
		return fmt.Errorf("RAKP 2 response returned with an error: %s", m2.StatusCode)
	}

	if consoleID != m2.ConsoleID {
		return fmt.Errorf("RAKP 2 response console session ID mismatch 0x%x - 0x%x", consoleID, m2.ConsoleID)
	}

	if err = m2.ValidateAuthCode(s.config, m1); err != nil {
		return err
	}

	// 4. Activate session(RAKP Message 3,4)
	m3 := &rakpMessage3{
		StatusCode: rakpStatusNoErrors,
		ManagedID:  osr.ManagedID,
	}
	m3.GenerateAuthCode(s.config, m1, m2)
	m3.GenerateSIK(s.config, m1, m2)
	m3.GenerateK1(s.config)
	m3.GenerateK2(s.config)

	err = retry(int(s.config.Retries), func() (e error) {
		req := &ipmiPacket{
			RMCPHeader:    newRMCPHeaderForIPMI(),
			SessionHeader: s.Header(payloadTypeRAKP3),
			Request:       m3,
		}
		pkt, e = s.SendPacket(req)
		return
	})
	if err != nil {
		return err
	}

	m4, ok := pkt.Response.(*rakpMessage4)
	if !ok {
		return errors.New("unexpected RAKP 4 response received")
	}
	if m4.StatusCode != rakpStatusNoErrors {
		return fmt.Errorf("RAKP 4 response returned with an error: %s", m4.StatusCode)
	}
	if consoleID != m4.ConsoleID {
		return fmt.Errorf("RAKP 4 reponse console session ID mismatch 0x%x - 0x%x", consoleID, m4.ConsoleID)
	}
	if err = m4.ValidateAuthCode(s.config, m1, m2, m3); err != nil {
		return err
	}

	// Set session ID
	s.id = osr.ManagedID
	s.k1 = m3.K1[:]
	s.k2 = m3.K2[:]

	// Set session privilege level
	if level := s.config.Role; level > RoleUser {
		if _, err := s.execute(newSetSessionPrivilegeCommand(level)); err != nil {
			return fmt.Errorf("unable to set session privilege level to %s", level)
		}
	}

	return nil
}

func (s *sessionV2_0) Close() error {
	if s.ActiveSession() {
		if err := s.Execute(newCloseSessionCommand(s.id)); err != nil {
			return err
		}

		s.id = 0
		s.sequence = 0
		s.rqSeq = 0
		s.k1 = nil
		s.k2 = nil
	}

	if c := s.conn; c != nil {
		if err := c.Close(); err != nil {
			return err
		}
		s.conn = nil
	}

	return nil
}

func (s *sessionV2_0) Execute(cmd Command) error {
	if err := s.Open(); err != nil {
		return err
	}

	if _, err := s.execute(cmd); err != nil {
		return err
	}
	return nil
}

func (s *sessionV2_0) execute(cmd Command) (response, error) {
	var res *ipmiPacket
	err := retry(int(s.config.Retries), func() (e error) {
		req := &ipmiPacket{
			RMCPHeader:    newRMCPHeaderForIPMI(),
			SessionHeader: s.Header(payloadTypeIPMI),
			Request: &ipmiRequestMessage{
				RsAddr:  bmcSlaveAddress,
				RqAddr:  remoteSWID,
				RqSeq:   s.NextRqSeq(),
				Command: cmd,
			},
		}
		res, e = s.SendPacket(req)
		return
	})
	if err != nil {
		return nil, err
	}

	rsm, ok := res.Response.(*ipmiResponseMessage)
	if !ok {
		return nil, fmt.Errorf("unexpected IPMI command response: %s", res)
	}

	if rsm.CompletionCode != CompletionOK {
		return nil, &CommandError{
			CompletionCode: rsm.CompletionCode,
			Command:        cmd,
		}
	}
	if _, err = cmd.Unmarshal(rsm.Data); err != nil {
		return nil, err
	}

	return res, nil
}

func (s *sessionV2_0) NextSequence() uint32 {
	if s.ActiveSession() {
		switch s.sequence {
		case math.MaxUint32:
			// wrap around
			s.sequence = 1
		default:
			s.sequence++
		}
	}
	return s.sequence
}

func (s *sessionV2_0) NextRqSeq() uint8 {
	n := s.rqSeq
	s.rqSeq++
	if s.rqSeq >= 64 {
		s.rqSeq = 0
	}
	return n << 2
}

func (s *sessionV2_0) SendPacket(req *ipmiPacket) (*ipmiPacket, error) {
	buf, err := req.Request.Marshal()
	if err != nil {
		return nil, err
	}
	req.PayloadBytes = buf
	req.SessionHeader.SetPayloadLength(len(buf))

	if s.ActiveSession() {
		// Encrypt the payload
		if requiredConfidentiality(s.config.CipherSuiteID) {
			req.SessionHeader.SetEncrypted(true)
			buf, err := encryptPayload(req.PayloadBytes, s.k2)
			if err != nil {
				return nil, err
			}
			req.PayloadBytes = buf
			req.SessionHeader.SetPayloadLength(len(buf))
		}
		// Append the session trailer
		if requiredIntegrity(s.config.CipherSuiteID) {
			// Trailer's source is the session header and payload
			req.SessionHeader.SetAuthenticated(true)
			msg, err := req.SessionHeader.Marshal()
			if err != nil {
				return nil, err
			}
			trailer := makeTrailer(append(msg, req.PayloadBytes...), s.k1)
			req.PayloadBytes = append(req.PayloadBytes, trailer...)
		}
	}

	res, msg, err := sendMessage(s.conn, req, s.config.Timeout)
	if err != nil {
		return nil, err
	}
	pkt, ok := res.(*ipmiPacket)
	if !ok {
		return nil, fmt.Errorf("unexpected IPMI response received: %s", res)
	}

	if s.ActiveSession() {
		if id := pkt.SessionHeader.ID(); consoleID != id {
			return nil, fmt.Errorf("console session ID mismatch 0x%x - 0x%x", consoleID, id)
		}

		if requiredIntegrity(s.config.CipherSuiteID) {
			if !pkt.SessionHeader.PayloadType().Authenticated() {
				return nil, errors.New("response message not authenticated")
			}
			if err := validateTrailer(msg[rmcpHeaderSize:], s.k1); err != nil {
				return nil, err
			}
		}

		if requiredConfidentiality(s.config.CipherSuiteID) {
			if !pkt.SessionHeader.PayloadType().Encrypted() {
				return nil, errors.New("response message not encrypted")
			}
			buf, err := decryptPayload(pkt.PayloadBytes, s.k2)
			if err != nil {
				return nil, err
			}
			pkt.PayloadBytes = buf
			pkt.SessionHeader.SetPayloadLength(len(buf))
		}
	}

	// Response unmarshal
	if _, err := pkt.Response.Unmarshal(pkt.PayloadBytes); err != nil {
		return nil, err
	}

	return pkt, nil
}

func (s *sessionV2_0) String() string {
	return fmt.Sprintf(`{ID:%d,"Sequence":%d,"RqSeq":%d,"K1":"%s","K2":"%s"}`,
		s.id, s.sequence, s.rqSeq, hex.EncodeToString(s.k1), hex.EncodeToString(s.k2))
}

func newSessionV2_0(c *Config) session {
	return &sessionV2_0{config: c}
}

// Section 13.29
func encryptPayload(src, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:16]) // AES-128
	if err != nil {
		return nil, err
	}

	// Add the pad and the pad length
	srcLen := len(src)
	padLen := 0
	if mod := (srcLen + 1) % aes.BlockSize; mod != 0 {
		padLen = aes.BlockSize - mod
	}
	input := make([]byte, srcLen+padLen+1)
	copy(input, src)

	for i := 0; i < padLen; i++ {
		input[srcLen+i] = byte(i + 1)
	}
	input[srcLen+padLen] = byte(padLen)

	// Initialization vector
	dst := make([]byte, aes.BlockSize+len(input))
	iv := dst[:aes.BlockSize]
	if _, err = rand.Read(iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(dst[aes.BlockSize:], input)

	return dst, nil
}

func decryptPayload(src, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:16]) // AES-128
	if err != nil {
		return nil, err
	}

	if l := len(src); l < aes.BlockSize || l%aes.BlockSize != 0 {
		return nil, fmt.Errorf("incorrect payload size - %d", l)
	}

	dst := make([]byte, len(src)-aes.BlockSize)
	iv, data := src[:aes.BlockSize], src[aes.BlockSize:]
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(dst, data)

	padLen := int(dst[len(dst)-1])
	return dst[:len(dst)-padLen-1], nil
}

func makeTrailer(src, key []byte) []byte {
	// Session Trailer (Table 13-8)
	// +---------------+
	// | Integrity PAD |  n bytes
	// | Pad Length    |  1 byte
	// | Next Header   |  1 byte  (0x07)
	// | AuthCode      | 12 bytes
	// +---------------+
	srcLen := len(src)
	padLen := 0
	if mod := (srcLen + 1 + 1 + 12) % 4; mod != 0 {
		padLen = 4 - mod
	}

	data := make([]byte, srcLen+padLen+2+12)
	copy(data, src)

	for i := 0; i < padLen; i++ {
		data[srcLen+i] = 0xff // Integrity Pad byte
	}
	data[srcLen+padLen] = byte(padLen)
	data[srcLen+padLen+1] = 0x07 // Next Header

	mac := hmac.New(sha1.New, key)
	mac.Write(data[:srcLen+padLen+2])
	// Use the first 12 bytes of the authcode
	authCode := mac.Sum(nil)
	copy(data[srcLen+padLen+2:], authCode[:12])

	return data[srcLen:]
}

func validateTrailer(src, key []byte) error {
	if l := len(src); l < 12 {
		return errors.New("payload has no auth code")
	}

	authCode := src[len(src)-12:]
	mac := hmac.New(sha1.New, key)
	mac.Write(src[:len(src)-12])

	if generated := mac.Sum(nil); !bytes.Equal(authCode, generated[:12]) {
		return fmt.Errorf(
			"received message with invalid authcode %s - %s",
			hex.EncodeToString(authCode), hex.EncodeToString(generated),
		)
	}

	return nil
}
