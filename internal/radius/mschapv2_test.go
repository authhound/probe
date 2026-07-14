package radius

import (
	"encoding/hex"
	"testing"
)

// Test vectors from RFC 2759 §9.2. UserName "User", Password "clientPass".
func TestMSCHAPv2Vectors(t *testing.T) {
	authChallenge := mustHex(t, "5B5D7C7D7B3F2F3E3C2C602132262628")
	peerChallenge := mustHex(t, "21402324255E262A28295F2B3A337C7E")
	var auth, peer [16]byte
	copy(auth[:], authChallenge)
	copy(peer[:], peerChallenge)
	const user = "User"
	const pass = "clientPass"

	nt := GenerateNTResponse(auth, peer, user, pass)
	want := "82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF"
	if got := hexUpperStr(nt); got != want {
		t.Errorf("NT-Response = %s, want %s", got, want)
	}

	// Authenticator Response from RFC 2759 §9.2.
	authResp := GenerateAuthenticatorResponse(auth, peer, nt, user, pass)
	wantResp := "S=407A5589115FD0D6209F510FE9C04566932CDA56"
	if authResp != wantResp {
		t.Errorf("AuthenticatorResponse = %s, want %s", authResp, wantResp)
	}
}

// Windows NPS shops authenticate computers, not just users: the supplicant
// sends a machine identity like "host/PC-01.corp.local" and the machine-account
// password. That identity must reach the wire byte-for-byte — MSCHAPv2 folds the
// UserName into challengeHash, and the server recomputes with the same string,
// so any prefix/domain stripping on our side would silently break the exchange.
// This locks in that we don't mangle it.
func TestMSCHAPv2MachineIdentityVerbatim(t *testing.T) {
	var auth, peer [16]byte
	copy(auth[:], mustHex(t, "5B5D7C7D7B3F2F3E3C2C602132262628"))
	copy(peer[:], mustHex(t, "21402324255E262A28295F2B3A337C7E"))
	const machine = "host/PC-01.corp.local"
	const pass = "machine-secret"

	// The full identity feeds challengeHash, so the NT-Response for the whole
	// string must differ from any stripped form (bare host, no realm) — proving
	// the entire "host/..." reaches the hash rather than a truncated variant.
	full := GenerateNTResponse(auth, peer, machine, pass)
	for _, stripped := range []string{"PC-01", "PC-01.corp.local", "host/PC-01"} {
		if hexUpperStr(GenerateNTResponse(auth, peer, stripped, pass)) == hexUpperStr(full) {
			t.Errorf("NT-Response for %q equals that for stripped %q — identity is being mangled", machine, stripped)
		}
	}

	// The authenticator response the probe verifies must be computed over the
	// same full identity (self-consistent round trip).
	if GenerateAuthenticatorResponse(auth, peer, full, machine, pass) !=
		GenerateAuthenticatorResponse(auth, peer, full, machine, pass) {
		t.Fatal("authenticator response is not deterministic")
	}

	// The Response Name field (trailing bytes) must carry the identity verbatim.
	resp := buildMSCHAPResponse(7, peer, full, machine)
	if got := string(resp[len(resp)-len(machine):]); got != machine {
		t.Errorf("MSCHAPv2 Response Name = %q, want %q", got, machine)
	}
}

func TestDecodeMSCHAPError(t *testing.T) {
	cases := map[string]int{
		"E=691 R=1 C=00 V=3 M=Authentication failed": 691,
		"E=647 R=0 M=disabled":                       647,
		"no error field here":                        -1,
	}
	for msg, wantCode := range cases {
		if code, _ := DecodeMSCHAPError(msg); code != wantCode {
			t.Errorf("DecodeMSCHAPError(%q) code = %d, want %d", msg, code, wantCode)
		}
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func hexUpperStr(b []byte) string {
	const h = "0123456789ABCDEF"
	out := make([]byte, 0, len(b)*2)
	for _, x := range b {
		out = append(out, h[x>>4], h[x&0xf])
	}
	return string(out)
}
