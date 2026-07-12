package radius

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"testing"
	"time"
)

// TestRadSecEndToEnd runs DialRadSec against an in-process RadSec server (a TLS
// listener that speaks RADIUS-over-TCP) — verifying the connect, TLS handshake,
// server-cert capture, and the RADIUS-over-TLS reply path together.
func TestRadSecEndToEnd(t *testing.T) {
	cert := selfSignedCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var hdr [20]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return
		}
		length := int(binary.BigEndian.Uint16(hdr[2:4]))
		req := make([]byte, length)
		copy(req, hdr[:])
		if length > 20 {
			io.ReadFull(conn, req[20:])
		}
		// Reply: Access-Reject, signed with the RadSec secret "radsec".
		reply := make([]byte, 20)
		reply[0] = byte(AccessReject)
		reply[1] = req[1]
		binary.BigEndian.PutUint16(reply[2:4], 20)
		h := md5.New()
		h.Write(reply[0:4])
		h.Write(req[4:20])
		h.Write([]byte("radsec"))
		copy(reply[4:20], h.Sum(nil))
		conn.Write(reply)
	}()

	res := DialRadSec(context.Background(), ln.Addr().String(), nil, "", 3*time.Second)
	if !res.Connected {
		t.Fatalf("not connected: %s", res.Reason)
	}
	if !res.TLSOK {
		t.Fatalf("TLS not ok: %s", res.Reason)
	}
	if len(res.Cert) == 0 {
		t.Error("no server cert captured")
	}
	if !res.RADIUSReplyOK {
		t.Error("no RADIUS reply over the tunnel")
	}
}

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "radsec.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
