package radius

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
)

// VerifyMessageAuthenticator reports whether a reply we received carries a
// Message-Authenticator attribute (RFC 3579 §3.2) and, if so, whether it is
// valid for the request we sent. This is the observation behind the
// BlastRADIUS (CVE-2024-3596) posture check: a server that signs its replies
// closes off the RADIUS/UDP reply-forgery class for this client entry.
//
//   - present=false: the reply has no Message-Authenticator at all — the
//     server accepted our (signed) request but did not sign its answer.
//   - present=true, valid=false: a Message-Authenticator is there but does not
//     verify with this shared secret (a wrong secret, or a malformed/tampered
//     attribute).
//   - present=true, valid=true: the server signed its reply correctly.
//
// raw is the exact bytes received; reqAuth is the Request Authenticator we sent
// (RFC 3579 keys the reply HMAC off the request's authenticator, not the
// reply's). This never mutates raw and never surfaces the secret.
func VerifyMessageAuthenticator(raw []byte, reqAuth [16]byte, secret string) (present, valid bool) {
	if len(raw) < 20 {
		return false, false
	}
	length := int(binary.BigEndian.Uint16(raw[2:4]))
	if length < 20 || length > len(raw) {
		return false, false
	}

	// Find the first Message-Authenticator attribute and note where its 16-octet
	// value sits, so we can zero it for the HMAC and compare against the original.
	off := -1
	pos := 20
	for pos+2 <= length {
		atype := AttrType(raw[pos])
		alen := int(raw[pos+1])
		if alen < 2 || pos+alen > length {
			return present, false // truncated attribute: can't validate
		}
		if atype == AttrMessageAuthenticator {
			if alen != 18 {
				// Wrong length for a Message-Authenticator: present but not valid.
				return true, false
			}
			off = pos + 2
			present = true
			break
		}
		pos += alen
	}
	if !present {
		return false, false
	}

	// RFC 3579 §3.2: HMAC-MD5 over (Type, Identifier, Length, Request
	// Authenticator, Attributes) with the Message-Authenticator value taken as
	// sixteen octets of zero. Work on a copy so raw is untouched.
	buf := make([]byte, length)
	copy(buf, raw[:length])
	copy(buf[4:20], reqAuth[:])     // reply carries the Response Auth; the HMAC uses the Request Auth
	for i := off; i < off+16; i++ { // zero the signature field
		buf[i] = 0
	}
	mac := hmac.New(md5.New, []byte(secret))
	mac.Write(buf)
	want := mac.Sum(nil)
	return true, hmac.Equal(raw[off:off+16], want)
}
