package radius

import "testing"

func attr(t AttrType, v ...byte) Attribute { return Attribute{Type: t, Value: v} }

func find(attrs []AuthAttr, name string) (AuthAttr, bool) {
	for _, a := range attrs {
		if a.Name == name {
			return a, true
		}
	}
	return AuthAttr{}, false
}

func TestAuthorizationAttributesVLAN(t *testing.T) {
	// A textbook 802.1X VLAN assignment: tagged Tunnel-Type/Medium-Type (RFC 2868
	// puts a Tag octet before the 3-octet value) and a tagged Tunnel-Private-
	// Group-ID string whose leading 0x01 is the tag, not part of the VLAN id.
	p := &Packet{Code: AccessAccept, Attributes: []Attribute{
		attr(AttrTunnelType, 0x00, 0x00, 0x00, 0x0d),       // VLAN (13)
		attr(AttrTunnelMediumType, 0x00, 0x00, 0x00, 0x06), // IEEE-802 (6)
		attr(AttrTunnelPrivateGroupID, 0x01, '2', '0'),     // tag 0x01 + "20"
		attr(AttrFilterID, 'G', 'u', 'e', 's', 't', 's'),
		attr(AttrSessionTimeout, 0x00, 0x00, 0x0e, 0x10), // 3600
	}}

	got := p.AuthorizationAttributes()
	want := map[string]string{
		"Tunnel-Type":             "VLAN (13)",
		"Tunnel-Medium-Type":      "IEEE-802 (6)",
		"Tunnel-Private-Group-ID": "20",
		"Filter-Id":               "Guests",
		"Session-Timeout":         "3600",
	}
	for name, wv := range want {
		a, ok := find(got, name)
		if !ok {
			t.Errorf("missing %s", name)
			continue
		}
		if a.Value != wv {
			t.Errorf("%s = %q, want %q", name, a.Value, wv)
		}
	}
}

func TestTunnelPrivateGroupIDUntagged(t *testing.T) {
	// No tag byte: a printable first byte ("2") means the whole value is the id.
	p := &Packet{Attributes: []Attribute{attr(AttrTunnelPrivateGroupID, '2', '0')}}
	a, ok := find(p.AuthorizationAttributes(), "Tunnel-Private-Group-ID")
	if !ok || a.Value != "20" {
		t.Errorf("untagged group id = %q (ok=%v), want 20", a.Value, ok)
	}
}

func TestAuthorizationAttributesVSA(t *testing.T) {
	// Vendor-Specific: 4-octet vendor id (Cisco = 9) then a type/len/value
	// sub-attribute (cisco-avpair). Decoded by name with the string value.
	av := []byte("shell:priv-lvl=15")
	vsa := []byte{0, 0, 0, 9, 1, byte(2 + len(av))}
	vsa = append(vsa, av...)
	p := &Packet{Attributes: []Attribute{attr(AttrVendorSpecific, vsa...)}}

	a, ok := find(p.AuthorizationAttributes(), "Cisco-AVPair")
	if !ok {
		t.Fatal("Cisco-AVPair not decoded")
	}
	if a.Value != "shell:priv-lvl=15" {
		t.Errorf("Cisco-AVPair value = %q", a.Value)
	}
	if a.Vendor != 9 {
		t.Errorf("Cisco-AVPair vendor = %d, want 9", a.Vendor)
	}
}

func TestAuthorizationAttributesSkipsMPPEKeys(t *testing.T) {
	// MS-MPPE-Send-Key/Recv-Key (vendor 311, types 16/17) ride every EAP accept
	// as encrypted key material. They must never be surfaced, but a real
	// authorization VSA in the same attribute still must be.
	key := make([]byte, 34)
	vsa := []byte{0, 0, 0x01, 0x37} // vendor 311
	vsa = append(vsa, 16, byte(2+len(key)))
	vsa = append(vsa, key...)
	vsa = append(vsa, 26, byte(2+3), 'v', '1', '0') // MS-Attr-26 = "v10"
	p := &Packet{Attributes: []Attribute{attr(AttrVendorSpecific, vsa...)}}

	got := p.AuthorizationAttributes()
	for _, a := range got {
		if a.Name == "MS-Attr-16" || a.Name == "MS-Attr-17" {
			t.Errorf("MPPE key surfaced: %+v", a)
		}
	}
	if _, ok := find(got, "MS-Attr-26"); !ok {
		t.Errorf("non-key MS VSA was dropped: %+v", got)
	}
}

func TestAuthorizationAttributesSkipsTransport(t *testing.T) {
	// Plumbing attributes (EAP-Message, Message-Authenticator, State) say nothing
	// about authorization and must not appear in the block.
	p := &Packet{Attributes: []Attribute{
		attr(AttrEAPMessage, 0x03, 0x01),
		attr(AttrState, 0xde, 0xad),
		attr(AttrMessageAuthenticator, 0x00),
		attr(AttrFilterID, 'x'),
	}}
	got := p.AuthorizationAttributes()
	if len(got) != 1 || got[0].Name != "Filter-Id" {
		t.Errorf("expected only Filter-Id, got %+v", got)
	}
}
