package masque

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// nicID is the single netstack interface backed by the tunnel.
const nicID tcpip.NICID = 1

// linkMTU is the netstack interface MTU. It must not exceed the tunnel's
// datagram budget (MaxIPPacket): a larger segment would fail SendIP and
// silently kill the outbound pump, blackholing the whole stack.
const linkMTU = MaxIPPacket

// packetQueue is the depth of the outbound (netstack -> tunnel) queue.
const packetQueue = 256

// ErrNoAnswer marks a resolver timeout.
var ErrNoAnswer = errors.New("dns: no answer")

// NetstackDialer dials TCP through a MASQUE tunnel via a gVisor userspace
// stack: the tunnel carries IP packets, netstack terminates TCP, and DNS
// resolves remotely (1.1.1.1 through the tunnel) so hostnames never leak.
type NetstackDialer struct {
	stack *stack.Stack
	chEP  *channel.Endpoint
	tun   *Tunnel
	ipv4  net.IP
	ipv6  net.IP

	dnsTimeout time.Duration
}

// NewNetstackDialer builds the userspace stack for the tunnel and starts the
// two pump goroutines (netstack -> tunnel, tunnel -> netstack). The dialer
// lives until the tunnel closes.
func NewNetstackDialer(tun *Tunnel, id *Identity) (*NetstackDialer, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	chEP := channel.New(packetQueue, linkMTU, "")
	if err := s.CreateNIC(nicID, chEP); err != nil {
		return nil, fmt.Errorf("create nic: %v", err)
	}
	assignedV4 := parseAssignedIP(id.IPv4)
	assignedV6 := parseAssignedIP(id.IPv6)
	if assignedV4 != nil {
		if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
			Protocol:          ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.AddrFrom4([4]byte(assignedV4.To4())).WithPrefix(),
		}, stack.AddressProperties{}); err != nil {
			return nil, fmt.Errorf("assign ipv4: %v", err)
		}
	}
	if assignedV6 != nil {
		if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
			Protocol:          ipv6.ProtocolNumber,
			AddressWithPrefix: tcpip.AddrFrom16([16]byte(assignedV6.To16())).WithPrefix(),
		}, stack.AddressProperties{}); err != nil {
			return nil, fmt.Errorf("assign ipv6: %v", err)
		}
	}
	var routes []tcpip.Route
	if assignedV4 != nil {
		routes = append(routes, tcpip.Route{
			Destination: header.IPv4EmptySubnet,
			NIC:         nicID,
		})
	}
	if assignedV6 != nil {
		routes = append(routes, tcpip.Route{
			Destination: header.IPv6EmptySubnet,
			NIC:         nicID,
		})
	}
	s.SetRouteTable(routes)

	d := &NetstackDialer{
		stack:      s,
		chEP:       chEP,
		tun:        tun,
		ipv4:       assignedV4,
		ipv6:       assignedV6,
		dnsTimeout: 5 * time.Second,
	}
	go d.pumpOut()
	go d.pumpIn()
	return d, nil
}

// pumpOut forwards netstack's outbound packets into the tunnel.
func (d *NetstackDialer) pumpOut() {
	for {
		pkt := d.chEP.ReadContext(context.Background())
		if pkt == nil {
			return // endpoint closed
		}
		b := pkt.ToView().AsSlice()
		err := d.tun.SendIP(b)
		pkt.DecRef()
		if err != nil {
			// Without an outbound path the netstack is dead; stop and let
			// the reconnect replace tunnel and dialer together.
			h2Debug("pumpOut stopped: %v", err)
			return
		}
	}
}

// pumpIn injects tunnel packets into netstack.
func (d *NetstackDialer) pumpIn() {
	ctx := context.Background()
	for {
		pkt, err := d.tun.RecvIP(ctx)
		if err != nil {
			return
		}
		proto := ipv4.ProtocolNumber
		if len(pkt) > 0 && pkt[0]>>4 == 6 {
			proto = ipv6.ProtocolNumber
		}
		pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(pkt),
		})
		d.chEP.InjectInbound(proto, pb)
		pb.DecRef()
	}
}

// Dial connects to "host:port" through the tunnel: hostnames resolve
// remotely, IP literals dial directly. Only TCP is supported, matching the
// proxy.Upstream contract.
func (d *NetstackDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("netstack dial: unsupported network %q", network)
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("netstack dial target %q: %w", addr, err)
	}
	port, err := parsePort(portStr)
	if err != nil {
		return nil, fmt.Errorf("netstack dial target %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		ip, err = d.Resolve(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", host, err)
		}
	}
	conn, err := d.dialTCP(ctx, ip, port)
	if err != nil {
		return nil, fmt.Errorf("connect %s: %w", addr, err)
	}
	return conn, nil
}

// dialTCP opens one TCP connection through the netstack and returns it as a
// net.Conn with blocking semantics.
func (d *NetstackDialer) dialTCP(ctx context.Context, ip net.IP, port int) (net.Conn, error) {
	proto := ipv4.ProtocolNumber
	var remote tcpip.Address
	if v4 := ip.To4(); v4 != nil {
		remote = tcpip.AddrFrom4([4]byte(v4))
	} else {
		remote = tcpip.AddrFrom16([16]byte(ip.To16()))
		proto = ipv6.ProtocolNumber
	}
	var wq waiter.Queue
	ep, err := d.stack.NewEndpoint(tcp.ProtocolNumber, proto, &wq)
	if err != nil {
		return nil, fmt.Errorf("endpoint: %v", err)
	}
	if err := waitConnected(ctx, ep, &wq, tcpip.FullAddress{NIC: nicID, Addr: remote, Port: uint16(port)}); err != nil {
		ep.Close()
		return nil, err
	}
	return &endpointConn{
		ep:     ep,
		wq:     &wq,
		local:  &net.TCPAddr{IP: d.ipv4},
		remote: &net.TCPAddr{IP: ip, Port: port},
	}, nil
}

// isConnectStarted reports whether err is the async connect marker.
func isConnectStarted(err tcpip.Error) bool {
	_, ok := err.(*tcpip.ErrConnectStarted)
	return ok
}

// waitConnected runs Connect to completion: register the waiter first (so a
// fast handshake cannot race the registration), start the connect, then wait
// for writability before asking for the result. gVisor's contract: the first
// Connect returns ErrConnectStarted; once the endpoint becomes writable the
// next Connect returns the final result.
func waitConnected(ctx context.Context, ep tcpip.Endpoint, wq *waiter.Queue,
	addr tcpip.FullAddress) error {
	entry, ch := waiter.NewChannelEntry(waiter.WritableEvents | waiter.EventHUp | waiter.EventErr)
	wq.EventRegister(&entry)
	defer wq.EventUnregister(&entry)
	err := ep.Connect(addr)
	for {
		if !isConnectStarted(err) {
			if err != nil {
				return fmt.Errorf("handshake: %v", err)
			}
			return nil
		}
		select {
		case <-ch:
		case <-ctx.Done():
			ep.Abort()
			return ctx.Err()
		}
		err = ep.Connect(tcpip.FullAddress{})
	}
}

// Resolve answers a hostname's first A record through the tunnel.
func (d *NetstackDialer) Resolve(ctx context.Context, host string) (net.IP, error) {
	ip := net.ParseIP(host)
	if ip != nil {
		return ip, nil
	}
	resp, err := d.dnsExchange(ctx, BuildAQuery(host))
	if err != nil {
		return nil, err
	}
	addrs, err := parseDNSMessageA(resp)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no A record for %s", host)
	}
	return addrs[0], nil
}

// dnsExchange sends one DNS query over UDP through the tunnel.
func (d *NetstackDialer) dnsExchange(ctx context.Context, query []byte) ([]byte, error) {
	proto := ipv4.ProtocolNumber
	ip := net.ParseIP(PublicDNS)
	var server tcpip.Address
	if v4 := ip.To4(); v4 != nil {
		server = tcpip.AddrFrom4([4]byte(v4))
	} else {
		server = tcpip.AddrFrom16([16]byte(ip.To16()))
		proto = ipv6.ProtocolNumber
	}
	var wq waiter.Queue
	ep, err := d.stack.NewEndpoint(udp.ProtocolNumber, proto, &wq)
	if err != nil {
		return nil, fmt.Errorf("endpoint: %v", err)
	}
	defer ep.Close()
	if err := ep.Connect(tcpip.FullAddress{NIC: nicID, Addr: server, Port: 53}); err != nil {
		return nil, fmt.Errorf("udp connect: %v", err)
	}
	cctx, cancel := context.WithTimeout(ctx, d.dnsTimeout)
	defer cancel()
	if _, err := ep.Write(bytes.NewReader(query), tcpip.WriteOptions{}); err != nil {
		return nil, fmt.Errorf("udp write: %v", err)
	}
	entry, ch := waiter.NewChannelEntry(waiter.ReadableEvents | waiter.EventErr)
	wq.EventRegister(&entry)
	defer wq.EventUnregister(&entry)
	for {
		buf := make([]byte, 1500)
		res, rerr := ep.Read(&bytesSliceWriter{p: buf}, tcpip.ReadOptions{})
		if rerr == nil {
			return buf[:res.Count], nil
		}
		if !isWouldBlock(rerr) {
			return nil, fmt.Errorf("udp read: %v", rerr)
		}
		select {
		case <-ch:
		case <-cctx.Done():
			return nil, ErrNoAnswer
		}
	}
}

// isWouldBlock reports whether err is the would-block marker.
func isWouldBlock(err tcpip.Error) bool {
	_, ok := err.(*tcpip.ErrWouldBlock)
	return ok
}

// parseAssignedIP strips the CIDR suffix and parses the address.
func parseAssignedIP(cidr string) net.IP {
	if i := len(cidr); i > 0 {
		for j := 0; j < i; j++ {
			if cidr[j] == '/' {
				cidr = cidr[:j]
				break
			}
		}
	}
	return net.ParseIP(cidr)
}

// parsePort converts a decimal port string.
func parsePort(s string) (int, error) {
	var port int
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, errors.New("bad port")
		}
		port = port*10 + int(s[i]-'0')
		if port > 65535 {
			return 0, errors.New("port out of range")
		}
	}
	if port < 1 {
		return 0, errors.New("port out of range")
	}
	return port, nil
}
