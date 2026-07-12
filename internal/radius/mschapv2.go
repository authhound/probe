package radius

import (
	"crypto/des"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"strconv"
	"strings"

	"golang.org/x/crypto/md4"
)

// MSCHAPv2 (RFC 2759) computations, used as the inner method of PEAP. All of
// this is client-side: the probe answers the server's challenge exactly as a
// supplicant would. Nothing here is reversible back to the password beyond what
// MSCHAPv2 itself exposes.

// ntPasswordHash = MD4(UTF-16LE(password)).
func ntPasswordHash(password string) []byte {
	u := utf16LE(password)
	h := md4.New()
	h.Write(u)
	return h.Sum(nil) // 16 bytes
}

func utf16LE(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		// MSCHAPv2 passwords are effectively UCS-2; keep the low 16 bits.
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

// challengeHash = SHA1(PeerChallenge || AuthenticatorChallenge || UserName)[:8].
func challengeHash(peer, auth [16]byte, userName string) []byte {
	h := sha1.New()
	h.Write(peer[:])
	h.Write(auth[:])
	h.Write([]byte(userName))
	return h.Sum(nil)[:8]
}

// challengeResponse implements the DES stage: three DES-ECB blocks keyed by the
// 21-byte zero-padded NT hash, encrypting the 8-byte challenge → 24 bytes.
func challengeResponse(challenge, ntHash []byte) []byte {
	var z [21]byte
	copy(z[:], ntHash)
	out := make([]byte, 0, 24)
	for i := 0; i < 3; i++ {
		block := desEncrypt(challenge, z[i*7:i*7+7])
		out = append(out, block...)
	}
	return out
}

// desEncrypt expands a 7-byte key to the 8-byte DES key (parity bits) and
// encrypts one 8-byte block in ECB mode.
func desEncrypt(clear, key7 []byte) []byte {
	k := make([]byte, 8)
	k[0] = key7[0]
	k[1] = (key7[0] << 7) | (key7[1] >> 1)
	k[2] = (key7[1] << 6) | (key7[2] >> 2)
	k[3] = (key7[2] << 5) | (key7[3] >> 3)
	k[4] = (key7[3] << 4) | (key7[4] >> 4)
	k[5] = (key7[4] << 3) | (key7[5] >> 5)
	k[6] = (key7[5] << 2) | (key7[6] >> 6)
	k[7] = key7[6] << 1
	for i := range k {
		k[i] = oddParity(k[i])
	}
	c, err := des.NewCipher(k)
	if err != nil {
		return make([]byte, 8)
	}
	out := make([]byte, 8)
	c.Encrypt(out, clear)
	return out
}

func oddParity(b byte) byte {
	ones := 0
	for i := 1; i < 8; i++ {
		if b&(1<<uint(i)) != 0 {
			ones++
		}
	}
	if ones%2 == 0 {
		return b | 1
	}
	return b &^ 1
}

// GenerateNTResponse produces the 24-byte NT-Response for an MSCHAPv2 exchange.
func GenerateNTResponse(authChallenge, peerChallenge [16]byte, userName, password string) []byte {
	ch := challengeHash(peerChallenge, authChallenge, userName)
	return challengeResponse(ch, ntPasswordHash(password))
}

var (
	magic1 = []byte{
		0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65,
		0x72, 0x20, 0x74, 0x6F, 0x20, 0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74,
		0x20, 0x73, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67, 0x20, 0x63, 0x6F,
		0x6E, 0x73, 0x74, 0x61, 0x6E, 0x74,
	}
	magic2 = []byte{
		0x50, 0x61, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6D, 0x61, 0x6B, 0x65,
		0x20, 0x69, 0x74, 0x20, 0x64, 0x6F, 0x20, 0x6D, 0x6F, 0x72, 0x65,
		0x20, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x6F, 0x6E, 0x65, 0x20, 0x69,
		0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F, 0x6E,
	}
)

// GenerateAuthenticatorResponse reproduces the server's expected "S=" value
// (RFC 2759 §8.7), letting the probe verify the server proved knowledge of the
// password — i.e. it's the real RADIUS server, not an impostor.
func GenerateAuthenticatorResponse(authChallenge, peerChallenge [16]byte, ntResponse []byte, userName, password string) string {
	pwHash := ntPasswordHash(password)
	h := md4.New()
	h.Write(pwHash)
	pwHashHash := h.Sum(nil)

	s1 := sha1.New()
	s1.Write(pwHashHash)
	s1.Write(ntResponse)
	s1.Write(magic1)
	digest := s1.Sum(nil)

	ch := challengeHash(peerChallenge, authChallenge, userName)
	s2 := sha1.New()
	s2.Write(digest)
	s2.Write(ch)
	s2.Write(magic2)
	resp := s2.Sum(nil)

	var sb strings.Builder
	sb.WriteString("S=")
	const hexUpper = "0123456789ABCDEF"
	for _, b := range resp {
		sb.WriteByte(hexUpper[b>>4])
		sb.WriteByte(hexUpper[b&0x0f])
	}
	return sb.String()
}

// NewPeerChallenge returns 16 random bytes for the client challenge.
func NewPeerChallenge() ([16]byte, error) {
	var c [16]byte
	_, err := rand.Read(c[:])
	return c, err
}

// DecodeMSCHAPError turns the "E=<code>" in an MSCHAPv2 Failure message into a
// plain-English cause. The message looks like:
//
//	E=691 R=1 C=<hex> V=3 M=Authentication failed
func DecodeMSCHAPError(failureMsg string) (code int, cause string) {
	code = -1
	for _, field := range strings.Fields(failureMsg) {
		if strings.HasPrefix(field, "E=") {
			if n, err := strconv.Atoi(strings.TrimPrefix(field, "E=")); err == nil {
				code = n
			}
		}
	}
	switch code {
	case 691:
		return code, "wrong username or password (ERROR_AUTHENTICATION_FAILURE). Also fires when the backend can't derive an NT hash — e.g. the directory only stores an SSHA/bcrypt password."
	case 646:
		return code, "outside the account's permitted logon hours (ERROR_RESTRICTED_LOGON_HOURS)."
	case 647:
		return code, "the account is disabled (ERROR_ACCT_DISABLED)."
	case 648:
		return code, "the password has expired (ERROR_PASSWD_EXPIRED)."
	case 649:
		return code, "the account has no network-access/dial-in permission (ERROR_NO_DIALIN_PERMISSION)."
	case 709:
		return code, "error changing password (ERROR_CHANGING_PASSWORD)."
	default:
		return code, "the server rejected the credentials."
	}
}

// buildMSCHAPResponse assembles the MSCHAPv2 Response type-data (the bytes
// after the EAP Type byte): OpCode(2) ID MS-Length ValueSize Response(49) Name.
func buildMSCHAPResponse(msChapID byte, peer [16]byte, ntResponse []byte, userName string) []byte {
	var resp [49]byte
	copy(resp[0:16], peer[:])
	// resp[16:24] reserved zeros
	copy(resp[24:48], ntResponse)
	resp[48] = 0 // flags
	name := []byte(userName)
	msLen := 1 + 1 + 2 + 1 + 49 + len(name) // OpCode..Name
	out := make([]byte, 0, msLen)
	out = append(out, 2, msChapID)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(msLen))
	out = append(out, l[:]...)
	out = append(out, 49)
	out = append(out, resp[:]...)
	out = append(out, name...)
	return out
}
