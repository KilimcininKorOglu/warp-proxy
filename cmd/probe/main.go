// Command probe is the stage-1 proof of the MASQUE port: it registers a WARP
// device (or loads the stored identity), opens the CONNECT-IP tunnel and
// sends a hand-built IPv4+UDP+DNS query through it. The TXT answer from
// whoami.cloudflare names the tunnel's egress IP; `warp=on` equivalent.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"warp-proxy/internal/masque"
)

const dnsServer = "1.1.1.1"

func main() {
	stateDir := flag.String("state", "state", "identity state directory")
	endpoint := flag.String("endpoint", "", "override the MASQUE endpoint (host:port)")
	reregister := flag.Bool("register", false, "force a fresh registration")
	timeout := flag.Duration("timeout", 30*time.Second, "overall budget")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	if err := run(ctx, *stateDir, *endpoint, *reregister); err != nil {
		fmt.Fprintln(os.Stderr, "probe failed:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, stateDir, endpoint string, force bool) error {
	id, err := loadOrRegister(ctx, stateDir, force)
	if err != nil {
		return err
	}
	fmt.Printf("identity: id=%s ipv4=%s endpoint=%s\n", id.ID, id.IPv4, endpointOr(id, endpoint))

	tunnel, err := masque.Dial(ctx, id, endpoint)
	if err != nil {
		return fmt.Errorf("tunnel: %w", err)
	}
	defer tunnel.Close()
	fmt.Printf("tunnel: MASQUE CONNECT -> %d OK\n", tunnel.Status())

	src := assignedV4(id.IPv4)
	if src == "" {
		return fmt.Errorf("identity has no IPv4 address")
	}
	answer, err := dnsQuery(ctx, tunnel, src, "whoami.cloudflare")
	if err != nil {
		return fmt.Errorf("dns through tunnel: %w", err)
	}
	fmt.Printf("whoami.cloudflare TXT: %s\n", answer)
	// The TXT carries either "ip=<addr>" or the bare address.
	egress := answer
	if i := strings.Index(answer, "ip="); i >= 0 {
		egress = answer[i+3:]
	}
	if ip := net.ParseIP(strings.TrimSpace(egress)); ip != nil {
		fmt.Printf("PROOF: tunnel egress is %s (a WARP address)\n", ip)
		return nil
	}
	return fmt.Errorf("answer %q carries no usable egress address", answer)
}

func loadOrRegister(ctx context.Context, dir string, force bool) (*masque.Identity, error) {
	if !force {
		if id, err := masque.LoadIdentity(dir); err == nil {
			fmt.Println("using stored identity")
			return id, nil
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("load identity: %w", err)
		}
	}
	fmt.Println("registering a fresh WARP device")
	id, err := masque.RegisterAuto(ctx, masque.Options{Name: "warp-proxy-probe"})
	if err != nil {
		return nil, err
	}
	if err := id.Save(dir); err != nil {
		return nil, fmt.Errorf("save identity: %w", err)
	}
	return id, nil
}

func endpointOr(id *masque.Identity, override string) string {
	if override != "" {
		return override
	}
	e, err := id.TunnelEndpoint()
	if err != nil {
		return "?"
	}
	return e
}

func assignedV4(cidr string) string {
	addr, _, _ := strings.Cut(cidr, "/")
	return addr
}

// dnsQuery sends one hand-built IPv4+UDP DNS TXT query through the tunnel
// and returns the first TXT string of the answer. No netstack is needed for
// this single fixed exchange.
func dnsQuery(ctx context.Context, t *masque.Tunnel, srcIP, name string) (string, error) {
	dns := buildDNSQuery(name)
	udp := buildUDP(0x4a7c, 53, dns)
	ip := buildIPv4(srcIP, dnsServer, udp)
	packet := append(ip, udp...)
	packet = append(packet, dns...)

	if err := t.SendIP(packet); err != nil {
		return "", fmt.Errorf("send: %w", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if time.Now().After(deadline) {
			return "", fmt.Errorf("no DNS answer within 10s")
		}
		recvCtx, cancel := context.WithDeadline(ctx, deadline)
		resp, err := t.RecvIP(recvCtx)
		cancel()
		if err != nil {
			return "", err
		}
		txt, ok := parseDNSAnswer(resp)
		if ok {
			return txt, nil
		}
	}
}

// buildIPv4 prepends a minimal IPv4 header (proto UDP) for the payload.
func buildIPv4(src, dst string, payload []byte) []byte {
	total := 20 + len(payload)
	h := make([]byte, 20)
	h[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(h[2:], uint16(total))
	h[4], h[5] = 0x1f, 0x9f // arbitrary identification
	h[6], h[7] = 0x40, 0x00 // DF
	h[8] = 64               // TTL
	h[9] = 17               // UDP
	copy(h[12:16], net.ParseIP(src).To4())
	copy(h[16:20], net.ParseIP(dst).To4())
	sum := ipv4Checksum(h)
	h[10], h[11] = byte(sum>>8), byte(sum)
	return h
}

func ipv4Checksum(h []byte) uint16 {
	var sum uint32
	for i := 0; i < len(h); i += 2 {
		sum += uint32(h[i])<<8 | uint32(h[i+1])
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// buildUDP prepends a UDP header with a zero checksum (valid over IPv4).
func buildUDP(srcPort, dstPort uint16, payload []byte) []byte {
	h := make([]byte, 8)
	binary.BigEndian.PutUint16(h[0:], srcPort)
	binary.BigEndian.PutUint16(h[2:], dstPort)
	binary.BigEndian.PutUint16(h[4:], uint16(8+len(payload)))
	return append(h, payload...)
}

// buildDNSQuery encodes one recursive TXT query for name.
func buildDNSQuery(name string) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, uint16(0x2b1f)) // id
	binary.Write(&b, binary.BigEndian, uint16(0x0100)) // RD
	binary.Write(&b, binary.BigEndian, uint16(1))      // QDCOUNT
	binary.Write(&b, binary.BigEndian, uint16(0))      // ANCOUNT
	binary.Write(&b, binary.BigEndian, uint16(0))      // NSCOUNT
	binary.Write(&b, binary.BigEndian, uint16(0))      // ARCOUNT
	for label := range strings.SplitSeq(name, ".") {
		b.WriteByte(byte(len(label)))
		b.WriteString(label)
	}
	b.WriteByte(0)
	binary.Write(&b, binary.BigEndian, uint16(16)) // TXT
	binary.Write(&b, binary.BigEndian, uint16(3))  // CHAOS: whoami.cloudflare answers in CH class
	return b.Bytes()
}

// parseDNSAnswer extracts the first TXT string of a DNS response; ok is
// false for any other packet.
func parseDNSAnswer(resp []byte) (string, bool) {
	if len(resp) < 28 {
		return "", false
	}
	ihl := int(resp[0]&0x0f) * 4
	if int(resp[9]) != 17 || len(resp) < ihl+8 {
		return "", false
	}
	d := resp[ihl+8:]
	if len(d) < 12 || d[0] != 0x2b || d[1] != 0x1f { // our DNS id
		return "", false
	}
	qr := d[2]&0x80 != 0
	ancount := int(binary.BigEndian.Uint16(d[6:8]))
	off := 12
	// Skip the question section.
	for d[off] != 0 {
		if d[off]&0xc0 != 0 { // compression pointer
			off++
			break
		}
		off += int(d[off]) + 1
	}
	off += 5 // terminating zero + qtype + qclass
	if !qr {
		return "", false
	}
	for i := 0; i < ancount && off+10 <= len(d); i++ {
		if d[off]&0xc0 == 0 {
			for d[off] != 0 {
				off += int(d[off]) + 1
			}
			off++
		} else { // name is a pointer
			off += 2
		}
		rtype := binary.BigEndian.Uint16(d[off:])
		rdlen := int(binary.BigEndian.Uint16(d[off+8:]))
		off += 10
		if rtype == 16 && off+rdlen <= len(d) {
			// TXT: one or more <len>strings; take the first.
			txtLen := int(d[off])
			if txtLen > 0 && off+1+txtLen <= len(d) {
				return string(d[off+1 : off+1+txtLen]), true
			}
		}
		off += rdlen
	}
	return "", false
}
