package radius

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"testing"
)

// signReply builds a reply packet (code, echoed id) carrying the given extra
// attributes and, when signMsgAuth is set, a correct Message-Authenticator
// computed the way a compliant server does (RFC 3579 §3.2: keyed off the
// request authenticator, signature field zeroed during the HMAC).
func signReply(code Code, reqAuth [16]byte, secret string, signMsgAuth bool, extra []byte) []byte {
	attrs := append([]byte(nil), extra...)
	var maOff int
	if signMsgAuth {
		maOff = 20 + len(attrs) + 2
		attrs = append(attrs, byte(AttrMessageAuthenticator), 18)
		attrs = append(attrs, make([]byte, 16)...)
	}
	pkt := make([]byte, 20+len(attrs))
	pkt[0] = byte(code)
	pkt[1] = 7 // identifier
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	// Response Authenticator field: any value — the reply MA HMAC ignores it and
	// uses the request authenticator instead.
	copy(pkt[4:20], reqAuth[:])
	copy(pkt[20:], attrs)

	if signMsgAuth {
		mac := hmac.New(md5.New, []byte(secret))
		mac.Write(pkt)
		copy(pkt[maOff:maOff+16], mac.Sum(nil))
	}
	return pkt
}

func TestVerifyMessageAuthenticator(t *testing.T) {
	var reqAuth [16]byte
	for i := range reqAuth {
		reqAuth[i] = byte(i + 1)
	}
	const secret = "s3cret"

	t.Run("valid signed reply", func(t *testing.T) {
		raw := signReply(AccessAccept, reqAuth, secret, true, nil)
		present, valid := VerifyMessageAuthenticator(raw, reqAuth, secret)
		if !present || !valid {
			t.Fatalf("got present=%v valid=%v, want true/true", present, valid)
		}
	})

	t.Run("valid signed reject with other attributes", func(t *testing.T) {
		// A Reply-Message (type 18) before the Message-Authenticator, to prove the
		// offset math holds when the MA is not the first attribute.
		extra := append([]byte{byte(AttrReplyMessage), 5}, []byte("bye")...)
		raw := signReply(AccessReject, reqAuth, secret, true, extra)
		present, valid := VerifyMessageAuthenticator(raw, reqAuth, secret)
		if !present || !valid {
			t.Fatalf("got present=%v valid=%v, want true/true", present, valid)
		}
	})

	t.Run("no message-authenticator", func(t *testing.T) {
		raw := signReply(AccessAccept, reqAuth, secret, false, nil)
		present, valid := VerifyMessageAuthenticator(raw, reqAuth, secret)
		if present || valid {
			t.Fatalf("got present=%v valid=%v, want false/false", present, valid)
		}
	})

	t.Run("tampered signature", func(t *testing.T) {
		raw := signReply(AccessAccept, reqAuth, secret, true, nil)
		raw[len(raw)-1] ^= 0xff // flip a byte of the MA value
		present, valid := VerifyMessageAuthenticator(raw, reqAuth, secret)
		if !present || valid {
			t.Fatalf("got present=%v valid=%v, want true/false", present, valid)
		}
	})

	t.Run("wrong secret", func(t *testing.T) {
		raw := signReply(AccessAccept, reqAuth, secret, true, nil)
		present, valid := VerifyMessageAuthenticator(raw, reqAuth, "different")
		if !present || valid {
			t.Fatalf("got present=%v valid=%v, want true/false", present, valid)
		}
	})

	t.Run("short packet", func(t *testing.T) {
		if present, valid := VerifyMessageAuthenticator([]byte{1, 2, 3}, reqAuth, secret); present || valid {
			t.Fatalf("short packet: got present=%v valid=%v, want false/false", present, valid)
		}
	})
}

// TestRequestAlwaysCarriesMessageAuthenticator pins constraint #1: every
// Access-Request the probe encodes carries a valid Message-Authenticator, so a
// hardened (BlastRADIUS-mitigated) server accepts it and the posture check can
// observe the reply. A regression here would silently break both.
func TestRequestAlwaysCarriesMessageAuthenticator(t *testing.T) {
	const secret = "s3cret"
	p, err := NewAccessRequest(1)
	if err != nil {
		t.Fatal(err)
	}
	p.AddString(AttrUserName, "authhound-probe")
	wire, err := p.encode(secret)
	if err != nil {
		t.Fatal(err)
	}

	// The request's own Message-Authenticator is keyed off its own authenticator
	// (which sits in bytes 4:20 of the request), so verify with that.
	var reqAuth [16]byte
	copy(reqAuth[:], wire[4:20])
	present, valid := VerifyMessageAuthenticator(wire, reqAuth, secret)
	if !present {
		t.Fatal("encoded Access-Request has no Message-Authenticator")
	}
	if !valid {
		t.Fatal("encoded Access-Request Message-Authenticator does not validate")
	}
}
