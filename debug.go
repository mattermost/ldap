package ldap

import (
	"bytes"
	"fmt"
	"log"

	"github.com/mattermost/mattermost-server/mlog"

	ber "gopkg.in/asn1-ber.v1"
)

// debugging type
//     - has a Printf method to write the debug output
type debugging bool

var tagMap = map[ber.Tag]string{
	ber.TagEOC:              "EOC (End-of-Content)",
	ber.TagBoolean:          "Boolean",
	ber.TagInteger:          "Integer",
	ber.TagBitString:        "Bit String",
	ber.TagOctetString:      "Octet String",
	ber.TagNULL:             "NULL",
	ber.TagObjectIdentifier: "Object Identifier",
	ber.TagObjectDescriptor: "Object Descriptor",
	ber.TagExternal:         "External",
	ber.TagRealFloat:        "Real (float)",
	ber.TagEnumerated:       "Enumerated",
	ber.TagEmbeddedPDV:      "Embedded PDV",
	ber.TagUTF8String:       "UTF8 String",
	ber.TagRelativeOID:      "Relative-OID",
	ber.TagSequence:         "Sequence and Sequence of",
	ber.TagSet:              "Set and Set OF",
	ber.TagNumericString:    "Numeric String",
	ber.TagPrintableString:  "Printable String",
	ber.TagT61String:        "T61 String",
	ber.TagVideotexString:   "Videotex String",
	ber.TagIA5String:        "IA5 String",
	ber.TagUTCTime:          "UTC Time",
	ber.TagGeneralizedTime:  "Generalized Time",
	ber.TagGraphicString:    "Graphic String",
	ber.TagVisibleString:    "Visible String",
	ber.TagGeneralString:    "General String",
	ber.TagUniversalString:  "Universal String",
	ber.TagCharacterString:  "Character String",
	ber.TagBMPString:        "BMP String",
}

// write debug output
func (debug debugging) Printf(format string, args ...interface{}) {
	if debug {
		log.Printf(format, args...)
	}
}

func (debug debugging) PrintPacket(packet *ber.Packet) {
	if debug {
		var b bytes.Buffer
		printPacket(&b, packet, 0)
		mlog.Debug(b.String())
		ber.PrintPacket(packet)
	}
}

func printPacket(out *bytes.Buffer, p *ber.Packet, indent int) {
	indent_str := ""

	for len(indent_str) != indent {
		indent_str += " "
	}

	class_str := ber.ClassMap[p.ClassType]

	tagtype_str := ber.TypeMap[p.TagType]

	tag_str := fmt.Sprintf("0x%02X", p.Tag)

	if p.ClassType == ber.ClassUniversal {
		tag_str = tagMap[p.Tag]
	}

	value := fmt.Sprint(p.Value)
	description := ""

	if p.Description != "" {
		description = p.Description + ": "
	}

	fmt.Fprintf(out, "%s%s(%s, %s, %s) Len=%d %q\n", indent_str, description, class_str, tagtype_str, tag_str, p.Data.Len(), value)

	for _, child := range p.Children {
		printPacket(out, child, indent+1)
	}
}
