package radius

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
)

// Authorization attributes an Access-Accept can carry to decide *which*
// VLAN/policy the authenticated session lands in (RFC 2865 / RFC 2868). A huge
// share of real 802.1X tickets are "auth works, but into the wrong VLAN" — the
// answer is in these attributes, so the probe surfaces them.
const (
	AttrServiceType          AttrType = 6
	AttrFramedProtocol       AttrType = 7
	AttrFilterID             AttrType = 11
	AttrVendorSpecific       AttrType = 26
	AttrSessionTimeout       AttrType = 27
	AttrIdleTimeout          AttrType = 28
	AttrTunnelType           AttrType = 64
	AttrTunnelMediumType     AttrType = 65
	AttrTunnelPrivateGroupID AttrType = 81
)

// AuthAttr is one decoded authorization attribute from an Access-Accept, in a
// form always safe to print: these attributes never carry secrets. Value is the
// human-readable decode; Raw (hex) and Vendor are set only for vendor-specific
// or otherwise opaque values so nothing is lost.
type AuthAttr struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Raw    string `json:"raw,omitempty"`    // hex, for VSAs / undecodable values
	Vendor int    `json:"vendor,omitempty"` // vendor id, for vendor-specific attributes
}

// AuthorizationAttributes decodes the authorization-relevant attributes the
// server returned, in the order they appear on the wire. Transport plumbing
// (EAP-Message, Message-Authenticator, State, Proxy-State) is skipped — those
// say nothing about the granted VLAN/policy. Unknown vendor attributes are kept
// as vendor id + raw hex rather than dropped.
func (p *Packet) AuthorizationAttributes() []AuthAttr {
	var out []AuthAttr
	for _, a := range p.Attributes {
		switch a.Type {
		case AttrServiceType:
			out = append(out, AuthAttr{Name: "Service-Type", Value: decodeEnum(a.Value, serviceTypeNames)})
		case AttrFramedProtocol:
			out = append(out, AuthAttr{Name: "Framed-Protocol", Value: decodeEnum(a.Value, framedProtocolNames)})
		case AttrFilterID:
			out = append(out, AuthAttr{Name: "Filter-Id", Value: string(a.Value)})
		case AttrSessionTimeout:
			out = append(out, AuthAttr{Name: "Session-Timeout", Value: decodeUint32(a.Value)})
		case AttrIdleTimeout:
			out = append(out, AuthAttr{Name: "Idle-Timeout", Value: decodeUint32(a.Value)})
		case AttrTunnelType:
			out = append(out, AuthAttr{Name: "Tunnel-Type", Value: decodeTaggedEnum(a.Value, tunnelTypeNames)})
		case AttrTunnelMediumType:
			out = append(out, AuthAttr{Name: "Tunnel-Medium-Type", Value: decodeTaggedEnum(a.Value, tunnelMediumNames)})
		case AttrTunnelPrivateGroupID:
			out = append(out, AuthAttr{Name: "Tunnel-Private-Group-ID", Value: decodeTaggedString(a.Value)})
		case AttrVendorSpecific:
			out = append(out, decodeVSA(a.Value)...)
		}
	}
	return out
}

var (
	serviceTypeNames    = map[uint32]string{1: "Login", 2: "Framed", 5: "Outbound", 6: "Administrative", 7: "NAS-Prompt", 8: "Authenticate-Only"}
	framedProtocolNames = map[uint32]string{1: "PPP", 2: "SLIP"}
	// RFC 2868 §3.1 Tunnel-Type: 13 = VLAN is the one that matters for 802.1X.
	tunnelTypeNames = map[uint32]string{1: "PPTP", 3: "L2TP", 11: "GRE", 13: "VLAN"}
	// RFC 2868 §3.2 Tunnel-Medium-Type: 6 = IEEE-802 accompanies a VLAN assignment.
	tunnelMediumNames = map[uint32]string{1: "IPv4", 2: "IPv6", 6: "IEEE-802"}
)

// decodeUint32 renders a 4-octet integer attribute as its decimal string.
func decodeUint32(v []byte) string {
	if len(v) != 4 {
		return "0x" + hex.EncodeToString(v)
	}
	return strconv.FormatUint(uint64(binary.BigEndian.Uint32(v)), 10)
}

// decodeEnum renders a 4-octet integer as a known name, falling back to the
// number when unrecognised (so an unknown value is still shown, never hidden).
func decodeEnum(v []byte, names map[uint32]string) string {
	if len(v) != 4 {
		return "0x" + hex.EncodeToString(v)
	}
	n := binary.BigEndian.Uint32(v)
	if name, ok := names[n]; ok {
		return fmt.Sprintf("%s (%d)", name, n)
	}
	return strconv.FormatUint(uint64(n), 10)
}

// decodeTaggedEnum decodes a tagged integer tunnel attribute (RFC 2868 §3.1):
// one Tag octet followed by a 3-octet value. The tag groups attributes of one
// tunnel together and is not part of the value.
func decodeTaggedEnum(v []byte, names map[uint32]string) string {
	if len(v) == 4 {
		n := uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
		if name, ok := names[n]; ok {
			return fmt.Sprintf("%s (%d)", name, n)
		}
		return strconv.FormatUint(uint64(n), 10)
	}
	// Untagged 4-octet integer (some servers omit the tag): decode as a plain enum.
	return decodeEnum(v, names)
}

// decodeTaggedString decodes a tagged string tunnel attribute (RFC 2868 §3.5,
// e.g. Tunnel-Private-Group-ID, which carries the VLAN id). A leading octet in
// the tag range 0x00–0x1F is the Tag and is stripped; a printable first byte
// (e.g. "20") means there is no tag.
func decodeTaggedString(v []byte) string {
	if len(v) > 0 && v[0] <= 0x1f {
		return string(v[1:])
	}
	return string(v)
}

// decodeVSA decodes a Vendor-Specific attribute (RFC 2865 §5.26): a 4-octet
// vendor id followed by one or more vendor sub-attributes in the common
// type/length/value format. Known sub-attributes are named; unknown ones are
// kept as vendor id + raw hex.
func decodeVSA(v []byte) []AuthAttr {
	if len(v) < 4 {
		return []AuthAttr{{Name: "Vendor-Specific", Value: "malformed", Raw: hex.EncodeToString(v)}}
	}
	vendor := binary.BigEndian.Uint32(v[0:4])
	rest := v[4:]
	var out []AuthAttr
	for len(rest) >= 2 {
		vtype := rest[0]
		vlen := int(rest[1])
		if isKeyingVSA(vendor, vtype) {
			// MS-MPPE-Send-Key / Recv-Key carry encrypted session key material,
			// not authorization. Never surface key bytes (trust: no secrets out).
			if vlen >= 2 && vlen <= len(rest) {
				rest = rest[vlen:]
				continue
			}
			return out
		}
		if vlen < 2 || vlen > len(rest) {
			// Not the standard sub-attribute framing (some vendors pack raw data):
			// surface the whole vendor blob rather than guessing.
			out = append(out, AuthAttr{
				Name:   fmt.Sprintf("Vendor-%d", vendor),
				Value:  printableOrHex(rest),
				Raw:    hex.EncodeToString(rest),
				Vendor: int(vendor),
			})
			return out
		}
		data := rest[2:vlen]
		out = append(out, AuthAttr{
			Name:   vsaName(vendor, vtype),
			Value:  printableOrHex(data),
			Raw:    hex.EncodeToString(data),
			Vendor: int(vendor),
		})
		rest = rest[vlen:]
	}
	if out == nil {
		out = append(out, AuthAttr{Name: fmt.Sprintf("Vendor-%d", vendor), Value: printableOrHex(rest), Raw: hex.EncodeToString(rest), Vendor: int(vendor)})
	}
	return out
}

// vsaName maps the handful of vendor sub-attributes the probe knows by name —
// deliberately small, focused on the ones that carry VLAN/policy. Everything
// else is shown as Vendor-<id>-Attr-<n> with the raw value preserved.
func vsaName(vendor uint32, vtype byte) string {
	switch {
	case vendor == 9 && vtype == 1: // Cisco: cisco-avpair (classic policy carrier)
		return "Cisco-AVPair"
	case vendor == 14122: // Aruba
		return fmt.Sprintf("Aruba-Attr-%d", vtype)
	case vendor == 311: // Microsoft
		return fmt.Sprintf("MS-Attr-%d", vtype)
	}
	return fmt.Sprintf("Vendor-%d-Attr-%d", vendor, vtype)
}

// isKeyingVSA reports whether a vendor sub-attribute carries session key
// material rather than authorization. MS-MPPE-Send-Key (311/16) and
// MS-MPPE-Recv-Key (311/17) appear on every EAP Access-Accept; their bytes are
// encrypted key material and must never be printed or logged.
func isKeyingVSA(vendor uint32, vtype byte) bool {
	return vendor == 311 && (vtype == 16 || vtype == 17)
}

// printableOrHex renders b as a string when it is all printable ASCII, else as
// "0x…" hex — so text values (Cisco-AVPair, filter names) read naturally while
// binary blobs stay unambiguous.
func printableOrHex(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return "0x" + hex.EncodeToString(b)
		}
	}
	return string(b)
}
