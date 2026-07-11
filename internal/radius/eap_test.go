package radius

import (
	"bytes"
	"testing"
)

func TestEAPMarshalParseRoundTrip(t *testing.T) {
	cases := []*EAPPacket{
		{Code: EAPResponse, ID: 7, Type: EAPTypeIdentity, Data: []byte("alice")},
		{Code: EAPResponse, ID: 0, Type: EAPTypeNak, Data: []byte{EAPTypePEAP}},
		{Code: EAPRequest, ID: 3, Type: EAPTypePEAP, Data: []byte{0x20}}, // TLS start flag
		{Code: EAPSuccess, ID: 9},
		{Code: EAPFailure, ID: 9},
	}
	for _, want := range cases {
		got, err := ParseEAP(want.Marshal())
		if err != nil {
			t.Fatalf("parse %v: %v", want, err)
		}
		if got.Code != want.Code || got.ID != want.ID || got.Type != want.Type || !bytes.Equal(got.Data, want.Data) {
			t.Errorf("round trip mismatch: got %+v want %+v", got, want)
		}
	}
}

func TestEAPMessageFragmentation(t *testing.T) {
	// An EAP packet larger than 253 bytes must split across multiple
	// EAP-Message attributes and reassemble identically.
	big := make([]byte, 600)
	for i := range big {
		big[i] = byte(i)
	}
	p := &Packet{Code: AccessRequest}
	p.AddEAP(big)
	n := 0
	for _, a := range p.Attributes {
		if a.Type == AttrEAPMessage {
			n++
			if len(a.Value) > 253 {
				t.Fatalf("fragment too long: %d", len(a.Value))
			}
		}
	}
	if n < 3 {
		t.Errorf("expected >=3 fragments for 600 bytes, got %d", n)
	}
	if !bytes.Equal(p.ConcatEAP(), big) {
		t.Error("reassembled EAP does not match original")
	}
}
