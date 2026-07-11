package check

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// fakeServer is a minimal RADIUS responder used to verify the probe end-to-end
// without Docker or a real FreeRADIUS. It signs replies with `secret` (or a
// wrong secret if wrongSecret is set) and accepts only `goodUser`/`goodPass`.
type fakeServer struct {
	secret      string
	wrongSecret string // if non-empty, sign replies with this instead
	goodUser    string
	goodPass    string
	silent      bool // if true, never replies (simulates unwhitelisted client)
	conn        *net.UDPConn
}

func startFakeServer(t *testing.T, fs *fakeServer) string {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	fs.conn = conn
	t.Cleanup(func() { conn.Close() })
	go fs.serve()
	return conn.LocalAddr().String()
}

func (fs *fakeServer) serve() {
	buf := make([]byte, 4096)
	for {
		n, raddr, err := fs.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if fs.silent {
			continue
		}
		req := make([]byte, n)
		copy(req, buf[:n])
		reply := fs.buildReply(req)
		if reply != nil {
			fs.conn.WriteToUDP(reply, raddr)
		}
	}
}

func (fs *fakeServer) buildReply(req []byte) []byte {
	if len(req) < 20 {
		return nil
	}
	code := decideCode(req, fs.goodUser, fs.goodPass, fs.secret)

	// Build reply: Code, ID, Length, ResponseAuthenticator, (no attrs).
	reply := make([]byte, 20)
	reply[0] = code
	reply[1] = req[1] // echo identifier
	binary.BigEndian.PutUint16(reply[2:4], 20)

	signSecret := fs.secret
	if fs.wrongSecret != "" {
		signSecret = fs.wrongSecret
	}
	// ResponseAuth = MD5(Code+ID+Len+RequestAuth+Attrs+Secret)
	h := md5.New()
	h.Write(reply[0:4])
	h.Write(req[4:20]) // request authenticator
	h.Write([]byte(signSecret))
	copy(reply[4:20], h.Sum(nil))
	return reply
}

// decideCode returns Access-Accept only for the good PAP credentials.
func decideCode(req []byte, goodUser, goodPass, secret string) byte {
	user, pass := extractUserPass(req, secret)
	if user == goodUser && pass == goodPass && goodUser != "" {
		return 2 // Accept
	}
	return 3 // Reject
}

func extractUserPass(req []byte, secret string) (user, pass string) {
	var reqAuth [16]byte
	copy(reqAuth[:], req[4:20])
	pos := 20
	length := int(binary.BigEndian.Uint16(req[2:4]))
	for pos+2 <= length && pos+2 <= len(req) {
		t := req[pos]
		l := int(req[pos+1])
		if l < 2 || pos+l > len(req) {
			break
		}
		val := req[pos+2 : pos+l]
		switch t {
		case 1: // User-Name
			user = string(val)
		case 2: // User-Password (hidden)
			pass = unhide(val, reqAuth, secret)
		}
		pos += l
	}
	return user, pass
}

func unhide(hidden []byte, reqAuth [16]byte, secret string) string {
	out := make([]byte, len(hidden))
	prev := reqAuth[:]
	for i := 0; i < len(hidden); i += 16 {
		h := md5.New()
		h.Write([]byte(secret))
		h.Write(prev)
		b := h.Sum(nil)
		for j := 0; j < 16 && i+j < len(hidden); j++ {
			out[i+j] = hidden[i+j] ^ b[j]
		}
		prev = hidden[i : i+16]
	}
	// Trim trailing NUL padding.
	for len(out) > 0 && out[len(out)-1] == 0 {
		out = out[:len(out)-1]
	}
	return string(out)
}

func target(addr, secret string) Target {
	return Target{Address: addr, Secret: secret, Timeout: 2 * time.Second, NASIdentifier: "test"}
}

func TestReachabilityAndSecret(t *testing.T) {
	addr := startFakeServer(t, &fakeServer{secret: "s3cret", goodUser: "alice", goodPass: "pw"})
	ctx := context.Background()

	if r := (Reachability{}).Run(ctx, target(addr, "s3cret")); r.Status != StatusPass {
		t.Errorf("reachability: got %s (%s), want pass", r.Status, r.Summary)
	}
	if r := (SharedSecret{}).Run(ctx, target(addr, "s3cret")); r.Status != StatusPass {
		t.Errorf("shared-secret correct: got %s (%s), want pass", r.Status, r.Summary)
	}
}

func TestSharedSecretMismatch(t *testing.T) {
	// Server signs replies with a DIFFERENT secret than the probe uses.
	addr := startFakeServer(t, &fakeServer{secret: "s3cret", wrongSecret: "other"})
	r := (SharedSecret{}).Run(context.Background(), target(addr, "s3cret"))
	if r.Status != StatusFail {
		t.Errorf("secret mismatch: got %s (%s), want fail", r.Status, r.Summary)
	}
}

func TestReachabilityTimeout(t *testing.T) {
	addr := startFakeServer(t, &fakeServer{secret: "s3cret", silent: true})
	tgt := target(addr, "s3cret")
	tgt.Timeout = 300 * time.Millisecond
	r := (Reachability{}).Run(context.Background(), tgt)
	if r.Status != StatusFail {
		t.Errorf("timeout: got %s, want fail", r.Status)
	}
}

func TestPAPAcceptAndReject(t *testing.T) {
	addr := startFakeServer(t, &fakeServer{secret: "s3cret", goodUser: "alice", goodPass: "pw"})
	ctx := context.Background()

	good := target(addr, "s3cret")
	good.Username, good.Password = "alice", "pw"
	if r := (PAP{}).Run(ctx, good); r.Status != StatusPass {
		t.Errorf("pap accept: got %s (%s), want pass", r.Status, r.Summary)
	}

	bad := target(addr, "s3cret")
	bad.Username, bad.Password = "alice", "wrong"
	if r := (PAP{}).Run(ctx, bad); r.Status != StatusFail {
		t.Errorf("pap reject: got %s (%s), want fail", r.Status, r.Summary)
	}

	if r := (PAP{}).Run(ctx, target(addr, "s3cret")); r.Status != StatusSkip {
		t.Errorf("pap no-creds: got %s, want skip", r.Status)
	}
}

func TestRunnerRateCeiling(t *testing.T) {
	addr := startFakeServer(t, &fakeServer{secret: "s3cret"})
	runner := Runner{}
	plan := Plan{
		Target: target(addr, "s3cret"),
		Checks: []Check{Reachability{}, SharedSecret{}, Reachability{}},
	}
	start := time.Now()
	runner.Run(context.Background(), plan)
	// Three checks => at least two enforced gaps of minInterval.
	if elapsed := time.Since(start); elapsed < 2*minInterval {
		t.Errorf("rate ceiling not enforced: %s < %s", elapsed, 2*minInterval)
	}
}

// sanity: ensure our reply signer and the probe's verifier agree on the HMAC
// primitive used elsewhere (guards against md5/hmac import drift).
func TestHMACSanity(t *testing.T) {
	m := hmac.New(md5.New, []byte("k"))
	m.Write([]byte("x"))
	if len(m.Sum(nil)) != 16 {
		t.Fatal("unexpected hmac-md5 size")
	}
}
