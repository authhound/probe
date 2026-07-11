package check

import (
	"encoding/binary"

	"github.com/authhound/probe/internal/radius"
)

// commonAttrs returns the NAS attributes common to every request the probe
// sends, so the server sees a request shaped like a real 802.1X client's.
func commonAttrs(t Target) []radius.Attribute {
	var a []radius.Attribute
	if t.NASIdentifier != "" {
		a = append(a, radius.Attribute{Type: radius.AttrNASIdentifier, Value: []byte(t.NASIdentifier)})
	}
	if t.NASPortType != 0 {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(t.NASPortType))
		a = append(a, radius.Attribute{Type: radius.AttrNASPortType, Value: b[:]})
	}
	if t.CalledStation != "" {
		a = append(a, radius.Attribute{Type: radius.AttrCalledStationID, Value: []byte(t.CalledStation)})
	}
	if t.CallingStation != "" {
		a = append(a, radius.Attribute{Type: radius.AttrCallingStationID, Value: []byte(t.CallingStation)})
	}
	return a
}

// addCommon applies commonAttrs to a packet being built.
func addCommon(p *radius.Packet, t Target) {
	for _, a := range commonAttrs(t) {
		p.Add(a.Type, a.Value)
	}
}
