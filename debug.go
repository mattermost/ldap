package ldap

import (
	"bytes"
	"log"

	ber "gopkg.in/asn1-ber.v1"
)

// debugging type
//     - has a Printf method to write the debug output
type debugging bool

// write debug output
func (debug debugging) Printf(format string, args ...interface{}) {
	if debug {
		log.Printf(format, args...)
	}
}

func (debug debugging) PrintPacket(packet *ber.Packet) {
	if debug {
		var b bytes.Buffer
		WritePacket(&b, packet, 0)
		log.Printf(b.String())
		ber.PrintPacket(packet)
	}
}
