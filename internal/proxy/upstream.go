// Package proxy implements the client facing HTTP and SOCKS5 proxy servers.
// Both route every connection through the warp-cli local proxy (upstream),
// so all client traffic exits through Cloudflare WARP.
package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Upstream dials target addresses through an HTTP CONNECT proxy
// (the warp-cli proxy in proxy mode).
type Upstream struct {
	// Addr is the upstream HTTP proxy "host:port".
	Addr string
	// Timeout bounds the CONNECT handshake. Zero means 30s.
	Timeout time.Duration
}

// handshakeTimeout returns the configured or default handshake timeout.
func (u *Upstream) handshakeTimeout() time.Duration {
	if u.Timeout > 0 {
		return u.Timeout
	}
	return 30 * time.Second
}

// Dial connects to addr through the upstream proxy and returns the live
// connection. Only "tcp" is supported; any other network is an error.
func (u *Upstream) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("upstream dial: unsupported network %q", network)
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", u.Addr)
	if err != nil {
		return nil, fmt.Errorf("dial upstream %s: %w", u.Addr, err)
	}
	extra, err := u.sendConnect(ctx, conn, addr)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if len(extra) > 0 {
		return &prefixConn{Conn: conn, prefix: extra}, nil
	}
	return conn, nil
}

// prefixConn replays bytes that the CONNECT handshake reader already
// consumed from the socket before handing the connection to the caller.
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

// sendConnect performs the HTTP CONNECT handshake on conn. Any bytes the
// response reader already buffered are returned so the caller can replay
// them to its peer.
func (u *Upstream) sendConnect(_ context.Context, conn net.Conn, target string) ([]byte, error) {
	deadline := time.Now().Add(u.handshakeTimeout())
	_ = conn.SetDeadline(deadline)
	defer conn.SetDeadline(time.Time{})

	probe := &http.Request{Method: http.MethodConnect}
	reqLine := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	if _, err := conn.Write([]byte(reqLine)); err != nil {
		return nil, fmt.Errorf("send CONNECT %s: %w", target, err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, probe)
	if err != nil {
		return nil, fmt.Errorf("read CONNECT response for %s: %w", target, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream refused CONNECT to %s: %s",
			target, strings.TrimSpace(resp.Status))
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
