package masque

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// buildAResponse assembles an IPv4+UDP DNS response carrying one A record.
func buildAResponse(name string, ip [4]byte, rcode int) []byte {
	var d bytes.Buffer
	d.Write([]byte{byte(dnsID >> 8), byte(dnsID & 0xff), 0x81, byte(rcode), 0, 1, 0, 1, 0, 0, 0, 0})
	for _, label := range splitName(name) {
		d.WriteByte(byte(len(label)))
		d.WriteString(label)
	}
	d.WriteByte(0)
	binary.Write(&d, binary.BigEndian, uint16(1)) // qtype A
	binary.Write(&d, binary.BigEndian, uint16(1)) // qclass IN
	binary.Write(&d, binary.BigEndian, uint16(0xc00c))
	binary.Write(&d, binary.BigEndian, uint16(1)) // A
	binary.Write(&d, binary.BigEndian, uint16(1)) // IN
	binary.Write(&d, binary.BigEndian, uint32(60))
	binary.Write(&d, binary.BigEndian, uint16(4))
	d.Write(ip[:])

	// Frame it as IPv4 + UDP.
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[4:], uint16(8+d.Len()))
	total := 20 + len(udp) + d.Len()
	h := make([]byte, 20)
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:], uint16(total))
	h[8] = 64
	h[9] = 17
	copy(h[12:16], net.IPv4(1, 1, 1, 1).To4())
	copy(h[16:20], net.IPv4(172, 16, 0, 2).To4())
	return append(append(h, udp...), d.Bytes()...)
}

func splitName(name string) []string {
	var out []string
	cur := ""
	for _, r := range name {
		if r == '.' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	return append(out, cur)
}

func TestParseDNSAnswerA(t *testing.T) {
	resp := buildAResponse("example.com", [4]byte{93, 184, 216, 34}, 0)
	body, err := dnsAnswerBody(resp)
	if err != nil {
		t.Fatalf("frame: %v", err)
	}
	addrs, err := parseAFromMessage(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(addrs) != 1 || !addrs[0].Equal(net.IPv4(93, 184, 216, 34)) {
		t.Errorf("addrs = %v", addrs)
	}
}

func TestParseDNSAnswerARcode(t *testing.T) {
	resp := buildAResponse("nope.example", [4]byte{1, 2, 3, 4}, 3)
	body, err := dnsAnswerBody(resp)
	if err != nil {
		t.Fatalf("frame: %v", err)
	}
	if _, err := parseAFromMessage(body); err == nil {
		t.Error("NXDOMAIN accepted")
	}
}

func TestParseDNSAnswerARejectsOthers(t *testing.T) {
	if _, err := dnsAnswerBody([]byte{1, 2, 3}); err == nil {
		t.Error("truncated packet accepted")
	}
	// A different DNS id must be rejected (DNS starts after IPv4+UDP).
	resp := buildAResponse("example.com", [4]byte{1, 2, 3, 4}, 0)
	resp[28] ^= 0xff
	if _, err := dnsAnswerBody(resp); err == nil {
		t.Error("foreign id accepted")
	}
}

func TestBuildAQueryShape(t *testing.T) {
	q := BuildAQuery("whoami.cloudflare")
	// header(12) + "whoami"(7 incl len byte) + "cloudflare"(11) + null + qtype + qclass
	if len(q) != 12+7+11+5 {
		t.Errorf("query = %d bytes, want %d", len(q), 12+7+11+5)
	}
	if q[2] != 0x01 {
		t.Error("RD flag missing")
	}
	if q[len(q)-4] != 0 || q[len(q)-3] != 1 {
		t.Error("qtype is not A")
	}
	if q[len(q)-2] != 0 || q[len(q)-1] != 1 {
		t.Error("qclass is not IN")
	}
}

func TestParseAssignedIP(t *testing.T) {
	if got := parseAssignedIP("100.96.0.3/32"); !got.Equal(net.IPv4(100, 96, 0, 3)) {
		t.Errorf("parseAssignedIP = %v", got)
	}
	if got := parseAssignedIP("garbage"); got != nil {
		t.Errorf("garbage parsed as %v", got)
	}
}

func TestParsePort(t *testing.T) {
	for _, ok := range []string{"1", "80", "65535"} {
		if _, err := parsePort(ok); err != nil {
			t.Errorf("parsePort(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "0", "65536", "80a"} {
		if _, err := parsePort(bad); err == nil {
			t.Errorf("parsePort(%q) accepted", bad)
		}
	}
}
