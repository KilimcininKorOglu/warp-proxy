package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

func TestBuildAndParseDNSRoundtrip(t *testing.T) {
	dns := buildDNSQuery("whoami.cloudflare")
	udp := buildUDP(0x4a7c, 53, dns)
	ip := buildIPv4("100.96.0.3", dnsServer, udp)
	packet := append(append(append([]byte{}, ip...), udp...), dns...)

	// The IPv4 header must checksum cleanly and carry proto UDP.
	if ipv4Checksum(packet[:20]) != 0 {
		t.Error("ipv4 checksum mismatch")
	}
	if packet[9] != 17 {
		t.Errorf("proto = %d, want 17 (UDP)", packet[9])
	}
	if !net.ParseIP("100.96.0.3").Equal(net.IP(packet[12:16])) {
		t.Error("source address wrong")
	}

	// Build a matching response: same DNS id, one TXT answer.
	txt := []byte("ip=104.28.240.1")
	resp := &bytes.Buffer{}
	resp.Write([]byte{0x2b, 0x1f, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0})
	for label := range strings.SplitSeq("whoami.cloudflare", ".") {
		resp.WriteByte(byte(len(label)))
		resp.WriteString(label)
	}
	resp.WriteByte(0)
	_ = binary.Write(resp, binary.BigEndian, uint16(16)) // qtype
	_ = binary.Write(resp, binary.BigEndian, uint16(1))  // qclass
	// Answer: name pointer, TXT, class IN, ttl, rdlength, string.
	_ = binary.Write(resp, binary.BigEndian, uint16(0xc00c))
	_ = binary.Write(resp, binary.BigEndian, uint16(16))
	_ = binary.Write(resp, binary.BigEndian, uint16(1))
	_ = binary.Write(resp, binary.BigEndian, uint32(300))
	_ = binary.Write(resp, binary.BigEndian, uint16(len(txt)+1))
	resp.WriteByte(byte(len(txt)))
	resp.Write(txt)

	full := append(append(append([]byte{}, packet[:20]...), udp[:8]...), resp.Bytes()...)
	// Fix the IPv4 length and checksum for the response framing.
	binary.BigEndian.PutUint16(full[2:], uint16(len(full)))
	sum := ipv4Checksum(full[:20])
	full[10], full[11] = byte(sum>>8), byte(sum)

	got, ok := parseDNSAnswer(full)
	if !ok {
		t.Fatal("parser rejected the response")
	}
	if got != "ip=104.28.240.1" {
		t.Errorf("txt = %q", got)
	}
}

func TestParseDNSAnswerRejectsGarbage(t *testing.T) {
	if _, ok := parseDNSAnswer([]byte{1, 2, 3}); ok {
		t.Error("accepted a truncated packet")
	}
	if _, ok := parseDNSAnswer(nil); ok {
		t.Error("accepted nil")
	}
}

func TestAssignedV4StripsCIDR(t *testing.T) {
	if got := assignedV4("100.96.0.3/32"); got != "100.96.0.3" {
		t.Errorf("assignedV4 = %q", got)
	}
	if got := assignedV4("100.96.0.3"); got != "100.96.0.3" {
		t.Errorf("assignedV4 = %q", got)
	}
}
