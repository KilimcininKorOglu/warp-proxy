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
	// A bytes.Buffer write never fails, so the error carries no information.
	_ = binary.Write(&b, binary.BigEndian, dnsID)
	_ = binary.Write(&b, binary.BigEndian, uint16(0x0100)) // RD
	_ = binary.Write(&b, binary.BigEndian, uint16(1))      // QDCOUNT
	_ = binary.Write(&b, binary.BigEndian, uint16(0))      // ANCOUNT
	_ = binary.Write(&b, binary.BigEndian, uint16(0))      // NSCOUNT
	_ = binary.Write(&b, binary.BigEndian, uint16(0))      // ARCOUNT
	for label := range strings.SplitSeq(name, ".") {
		b.WriteByte(byte(len(label))) // #nosec G115 -- resolver names, labels < 64 bytes
		b.WriteString(label)
	}
	b.WriteByte(0)
	_ = binary.Write(&b, binary.BigEndian, qtype)
	_ = binary.Write(&b, binary.BigEndian, qclass)
	return b.Bytes()
}

// BuildAQuery encodes one recursive A query for name.
func BuildAQuery(name string) []byte {
	return buildDNSQuery(name, 1, 1)
}

// BuildAAAAQuery encodes one recursive AAAA (IPv6) query for name.
func BuildAAAAQuery(name string) []byte {
	return buildDNSQuery(name, 28, 1)
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
	return parseDNSMessageRecords(d, 1, 4)
}

// parseDNSMessageAAAA returns the AAAA records of a bare DNS message.
func parseDNSMessageAAAA(d []byte) ([]net.IP, error) {
	return parseDNSMessageRecords(d, 28, 16)
}

// parseDNSMessageRecords validates the bare DNS message header and returns
// the answer records of rtype with size-byte RDATA.
func parseDNSMessageRecords(d []byte, rtype, size int) ([]net.IP, error) {
	if len(d) < 12 || d[0] != byte(dnsID>>8&0xff) || d[1] != byte(dnsID&0xff) {
		return nil, errNotOurDNS
	}
	if d[2]&0x80 == 0 {
		return nil, errNotOurDNS // not a response
	}
	return parseRecords(d, rtype, size)
}

// parseAFromMessage walks the answer section of a validated DNS message.
func parseAFromMessage(d []byte) ([]net.IP, error) {
	return parseRecords(d, 1, 4)
}

// parseRecords collects answer records of rtype with rdlen-byte addresses.
func parseRecords(d []byte, rtype, size int) ([]net.IP, error) {
	if rcode := d[3] & 0x0f; rcode != 0 {
		return nil, fmt.Errorf("dns rcode %d", rcode)
	}
	var out []net.IP
	eachAnswer(d, func(rt uint16, data []byte) {
		if int(rt) == rtype && len(data) == size {
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
	for range ancount {
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

// parseTXTFromMessage returns the first TXT string of a bare DNS message.
func parseTXTFromMessage(d []byte) (string, error) {
	if err := validateDNSResponse(d); err != nil {
		return "", err
	}
	ancount := int(binary.BigEndian.Uint16(d[6:8]))
	off := skipQuestion(d)
	for i := 0; i < ancount && off+10 <= len(d); i++ {
		off = skipName(d, off)
		if off+10 > len(d) {
			break
		}
		rdlen := int(binary.BigEndian.Uint16(d[off+8:]))
		off += 10
		if txt, ok := firstTXTString(d, off, rdlen); ok {
			return txt, nil
		}
		off += rdlen
	}
	return "", errors.New("no TXT record in answer")
}

// validateDNSResponse checks the id, the QR flag and the rcode.
func validateDNSResponse(d []byte) error {
	if len(d) < 12 || d[0] != byte(dnsID>>8&0xff) || d[1] != byte(dnsID&0xff) {
		return errNotOurDNS
	}
	if d[2]&0x80 == 0 {
		return errNotOurDNS
	}
	if rcode := d[3] & 0x0f; rcode != 0 {
		return fmt.Errorf("dns rcode %d", rcode)
	}
	return nil
}

// firstTXTString reads the first <len>string of a TXT record at off; ok is
// false for any other record type or a malformed one.
func firstTXTString(d []byte, off, rdlen int) (string, bool) {
	rtype := binary.BigEndian.Uint16(d[off-10:])
	if rtype != 16 || rdlen <= 0 || off+rdlen > len(d) {
		return "", false
	}
	n := int(d[off])
	if n > 0 && off+1+n <= off+rdlen {
		return string(d[off+1 : off+1+n]), true
	}
	return "", false
}

// dnsAnswerBody strips the IPv4+UDP frame from a tunnel datagram response
// and validates the DNS header underneath.
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
