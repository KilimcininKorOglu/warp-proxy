package masque

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

// PublicDNS is the resolver the tunnel uses for remote DNS.
const PublicDNS = "1.1.1.1"

// dnsID is the fixed transaction id of our queries; one query at a time
// travels per connection, so a fixed id is unambiguous.
const dnsID uint16 = 0x2b1f

// buildDNSQuery encodes one recursive query for name with the given type and
// class (e.g. type A class IN, or type TXT class CHAOS).
func buildDNSQuery(name string, qtype, qclass uint16) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, dnsID)
	binary.Write(&b, binary.BigEndian, uint16(0x0100)) // RD
	binary.Write(&b, binary.BigEndian, uint16(1))      // QDCOUNT
	binary.Write(&b, binary.BigEndian, uint16(0))      // ANCOUNT
	binary.Write(&b, binary.BigEndian, uint16(0))      // NSCOUNT
	binary.Write(&b, binary.BigEndian, uint16(0))      // ARCOUNT
	for _, label := range strings.Split(name, ".") {
		b.WriteByte(byte(len(label)))
		b.WriteString(label)
	}
	b.WriteByte(0)
	binary.Write(&b, binary.BigEndian, qtype)
	binary.Write(&b, binary.BigEndian, qclass)
	return b.Bytes()
}

// BuildAQuery encodes one recursive A query for name.
func BuildAQuery(name string) []byte {
	return buildDNSQuery(name, 1, 1)
}

// BuildTXTQuery encodes one recursive TXT query for name (CHAOS class, the
// class whoami.cloudflare answers in).
func BuildTXTQuery(name string) []byte {
	return buildDNSQuery(name, 16, 3)
}

// errNotOurDNS marks a response that does not answer our single question.
var errNotOurDNS = errors.New("not a response to our query")

// parseDNSMessageA returns the A records of a bare DNS message (as delivered
// by a netstack UDP endpoint, which terminates IP and UDP).
func parseDNSMessageA(d []byte) ([]net.IP, error) {
	if len(d) < 12 || d[0] != byte(dnsID>>8&0xff) || d[1] != byte(dnsID&0xff) {
		return nil, errNotOurDNS
	}
	if d[2]&0x80 == 0 {
		return nil, errNotOurDNS // not a response
	}
	return parseAFromMessage(d)
}

// parseAFromMessage walks the answer section of a validated DNS message.
func parseAFromMessage(d []byte) ([]net.IP, error) {
	if rcode := d[3] & 0x0f; rcode != 0 {
		return nil, fmt.Errorf("dns rcode %d", rcode)
	}
	var out []net.IP
	eachAnswer(d, func(rtype uint16, data []byte) {
		if rtype == 1 && len(data) == 4 {
			out = append(out, net.IP(data))
		}
	})
	return out, nil
}

// eachAnswer visits every record in the answer section of a validated DNS
// message with the record type and RDATA slice.
func eachAnswer(d []byte, visit func(rtype uint16, data []byte)) {
	ancount := int(binary.BigEndian.Uint16(d[6:8]))
	off := skipQuestion(d)
	for i := 0; i < ancount; i++ {
		if off+10 > len(d) {
			return
		}
		off = skipName(d, off)
		if off+10 > len(d) {
			return
		}
		rtype := binary.BigEndian.Uint16(d[off:])
		rdlen := int(binary.BigEndian.Uint16(d[off+8:]))
		off += 10
		if off+rdlen > len(d) {
			return
		}
		visit(rtype, d[off:off+rdlen])
		off += rdlen
	}
}

// parseDNSAnswerTXT returns the first TXT string of an IP-framed response.
func parseDNSAnswerTXT(resp []byte) (string, error) {
	d, err := dnsAnswerBody(resp)
	if err != nil {
		return "", err
	}
	ancount := int(binary.BigEndian.Uint16(d[6:8]))
	if rcode := d[3] & 0x0f; rcode != 0 {
		return "", fmt.Errorf("dns rcode %d", rcode)
	}
	off := skipQuestion(d)
	for i := 0; i < ancount && off+10 <= len(d); i++ {
		off = skipName(d, off)
		if off+10 > len(d) {
			break
		}
		rtype := binary.BigEndian.Uint16(d[off:])
		rdlen := int(binary.BigEndian.Uint16(d[off+8:]))
		off += 10
		if rtype == 16 && rdlen > 0 && off+rdlen <= len(d) {
			n := int(d[off])
			if n > 0 && off+1+n <= off+rdlen {
				return string(d[off+1 : off+1+n]), nil
			}
		}
		off += rdlen
	}
	return "", errors.New("no TXT record in answer")
}

// dnsAnswerBody validates the response header and returns the DNS payload.
func dnsAnswerBody(resp []byte) ([]byte, error) {
	if len(resp) < 20 {
		return nil, errNotOurDNS
	}
	ihl := int(resp[0]&0x0f) * 4
	if ihl < 20 || int(resp[9]) != 17 || len(resp) < ihl+12 {
		return nil, errNotOurDNS
	}
	d := resp[ihl+8:]
	if len(d) < 12 || d[0] != byte(dnsID>>8&0xff) || d[1] != byte(dnsID&0xff) {
		return nil, errNotOurDNS
	}
	if d[2]&0x80 == 0 {
		return nil, errNotOurDNS // not a response
	}
	return d, nil
}

// skipQuestion advances past the question section.
func skipQuestion(d []byte) int {
	off := skipName(d, 12)
	return off + 4 // qtype + qclass
}

// skipName advances past one (possibly compressed) name at off.
func skipName(d []byte, off int) int {
	for off < len(d) {
		l := int(d[off])
		if l == 0 {
			return off + 1
		}
		if l&0xc0 != 0 {
			return off + 2
		}
		off += l + 1
	}
	return off
}
