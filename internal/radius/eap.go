package radius

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// EAP (RFC 3748) codes and types used by the probe.
const (
	EAPRequest  byte = 1
	EAPResponse byte = 2
	EAPSuccess  byte = 3
	EAPFailure  byte = 4
)

const (
	EAPTypeIdentity byte = 1
	EAPTypeNak      byte = 3
	EAPTypeTLS      byte = 13
	EAPTypeTTLS     byte = 21
	EAPTypePEAP     byte = 25
	EAPTypeMSCHAPv2 byte = 26
	EAPTypeTLV      byte = 33 // PEAP Result-TLV (extensions)
)

// EAP-TLS/PEAP flags (RFC 5216 §3.1). The same framing carries TLS records for
// EAP-TLS, PEAP, and EAP-TTLS.
const (
	tlsFlagLength byte = 0x80 // TLS Message Length field present
	tlsFlagMore   byte = 0x40 // more fragments follow
	tlsFlagStart  byte = 0x20 // start
)

// EAPPacket is a parsed EAP message. Type is 0 for Success/Failure (which carry
// no type byte).
type EAPPacket struct {
	Code byte
	ID   byte
	Type byte
	Data []byte
}

func ParseEAP(b []byte) (*EAPPacket, error) {
	if len(b) < 4 {
		return nil, errors.New("eap: short packet")
	}
	length := int(binary.BigEndian.Uint16(b[2:4]))
	if length < 4 || length > len(b) {
		return nil, fmt.Errorf("eap: bad length %d (have %d)", length, len(b))
	}
	e := &EAPPacket{Code: b[0], ID: b[1]}
	if e.Code == EAPRequest || e.Code == EAPResponse {
		if length < 5 {
			return nil, errors.New("eap: request/response without type")
		}
		e.Type = b[4]
		e.Data = append([]byte(nil), b[5:length]...)
	}
	return e, nil
}

func (e *EAPPacket) Marshal() []byte {
	if e.Code == EAPSuccess || e.Code == EAPFailure {
		out := make([]byte, 4)
		out[0], out[1] = e.Code, e.ID
		binary.BigEndian.PutUint16(out[2:4], 4)
		return out
	}
	length := 5 + len(e.Data)
	out := make([]byte, length)
	out[0], out[1] = e.Code, e.ID
	binary.BigEndian.PutUint16(out[2:4], uint16(length))
	out[4] = e.Type
	copy(out[5:], e.Data)
	return out
}
