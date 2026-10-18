// Package proxy implements the client facing HTTP and SOCKS5 proxy servers.
// Both route every connection through the warp-cli local proxy (upstream),
// so all client traffic exits through Cloudflare WARP.
package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// Upstream dials target addresses through a SOCKS5 proxy: the warp-cli
// local proxy, whose native protocol is SOCKS5.
type Upstream struct {
	// Addr is the upstream SOCKS5 proxy "host:port".
	Addr string
	// Timeout bounds the SOCKS5 handshake. Zero means 30s.
	Timeout time.Duration
	// Front, when set, may rewrite "host:port" to a Cloudflare front
	// edge IP before the SOCKS5 CONNECT. It receives the context and the
	// original address and returns the address to dial plus whether it
	// changed anything.
	Front func(ctx context.Context, hostPort string) (string, bool)
}

// handshakeTimeout returns the configured or default handshake timeout.
func (u *Upstream) handshakeTimeout() time.Duration {
	if u.Timeout > 0 {
		return u.Timeout
	}
	return 30 * time.Second
}

// Dial connects to addr through the upstream SOCKS5 proxy and returns the
// live connection. Only "tcp" is supported; any other network is an error.
func (u *Upstream) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("upstream dial: unsupported network %q", network)
	}

	connectAddr := addr
	if u.Front != nil {
		if rewritten, changed := u.Front(ctx, addr); changed {
			connectAddr = rewritten
		}
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", u.Addr)
	if err != nil {
		return nil, fmt.Errorf("dial upstream %s: %w", u.Addr, err)
	}
	extra, err := u.handshake(conn, connectAddr)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if len(extra) > 0 {
		return &prefixConn{Conn: conn, prefix: extra}, nil
	}
	return conn, nil
}

// handshake performs the SOCKS5 no-auth CONNECT handshake. Any bytes read
// past the reply are returned so the caller can replay them.
func (u *Upstream) handshake(conn net.Conn, target string) ([]byte, error) {
	_ = conn.SetDeadline(time.Now().Add(u.handshakeTimeout()))
	defer conn.SetDeadline(time.Time{})

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("upstream target %q: %w", target, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("upstream target %q: bad port", target)
	}

	// Greeting: version 5, one method, no authentication.
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return nil, fmt.Errorf("socks greeting to %s: %w", u.Addr, err)
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(conn, greet); err != nil {
		return nil, fmt.Errorf("socks greeting read: %w", err)
	}
	if greet[0] != 0x05 || greet[1] != 0x00 {
		return nil, fmt.Errorf("socks proxy %s rejected the no-auth method", u.Addr)
	}

	req, err := socksConnectRequest(host, port)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(req); err != nil {
		return nil, fmt.Errorf("socks connect to %s: %w", target, err)
	}

	br := bufio.NewReader(conn)
	if err := readSocksReply(br); err != nil {
		return nil, err
	}
	if n := br.Buffered(); n > 0 {
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, fmt.Errorf("read buffered bytes: %w", err)
		}
		return buf, nil
	}
	return nil, nil
}

// socksConnectRequest builds a SOCKS5 CONNECT request. Hostnames travel as
// domain names so the upstream resolves them; IP literals travel as such.
func socksConnectRequest(host string, port int) ([]byte, error) {
	head := []byte{0x05, 0x01, 0x00} // VER, CMD=CONNECT, RSV
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req := append(head, 0x01) // ATYP=IPv4
			req = append(req, v4...)
			return append(req, byte(port>>8), byte(port)), nil
		}
		req := append(head, 0x04) // ATYP=IPv6
		req = append(req, ip.To16()...)
		return append(req, byte(port>>8), byte(port)), nil
	}
	if len(host) > 255 {
		return nil, errors.New("upstream target hostname too long")
	}
	req := append(head, 0x03, byte(len(host))) // ATYP=domain
	req = append(req, host...)
	return append(req, byte(port>>8), byte(port)), nil
}

// readSocksReply reads the CONNECT reply and skips the bound address.
func readSocksReply(br *bufio.Reader) error {
	head := make([]byte, 4)
	if _, err := io.ReadFull(br, head); err != nil {
		return fmt.Errorf("socks reply read: %w", err)
	}
	if head[0] != 0x05 {
		return fmt.Errorf("socks reply: bad version %d", head[0])
	}
	if head[1] != 0x00 {
		return fmt.Errorf("socks proxy refused CONNECT: reply code %d", head[1])
	}
	switch head[3] {
	case 0x01: // IPv4
		if _, err := io.CopyN(io.Discard, br, 4+2); err != nil {
			return fmt.Errorf("socks reply bind addr: %w", err)
		}
	case 0x03: // domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(br, lenBuf); err != nil {
			return fmt.Errorf("socks reply bind addr: %w", err)
		}
		if _, err := io.CopyN(io.Discard, br, int64(lenBuf[0])+2); err != nil {
			return fmt.Errorf("socks reply bind addr: %w", err)
		}
	case 0x04: // IPv6
		if _, err := io.CopyN(io.Discard, br, 16+2); err != nil {
			return fmt.Errorf("socks reply bind addr: %w", err)
		}
	default:
		return fmt.Errorf("socks reply: bad address type %d", head[3])
	}
	return nil
}

// prefixConn replays bytes that the handshake reader already consumed from
// the socket before handing the connection to the caller.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}
