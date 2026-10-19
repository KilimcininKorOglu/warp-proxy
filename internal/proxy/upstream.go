// Package proxy implements the client facing HTTP and SOCKS5 proxy servers.
// Both route every connection through the Upstream dial function, so all
// client traffic exits through the WARP tunnel.
package proxy

import (
	"context"
	"fmt"
	"net"
	"time"
)

// Upstream dials target addresses through its DialFunc: the WARP tunnel's
// netstack.
type Upstream struct {
	// DialFunc connects to "host:port" through the tunnel. Hostnames are
	// resolved remotely, inside the tunnel.
	DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)
	// Timeout bounds the dial. Zero means 30s.
	Timeout time.Duration
	// Front, when set, may rewrite "host:port" to a Cloudflare front edge
	// IP before the dial. It receives the context and the original address
	// and returns the address to dial plus whether it changed anything.
	Front func(ctx context.Context, hostPort string) (string, bool)
	// Resolve, when set, resolves hostnames through the tunnel for the
	// SOCKS5 server, so client hostnames never touch the host resolver.
	Resolve func(ctx context.Context, host string) (net.IP, error)
}

// handshakeTimeout returns the configured or default dial timeout.
func (u *Upstream) handshakeTimeout() time.Duration {
	if u.Timeout > 0 {
		return u.Timeout
	}
	return 30 * time.Second
}

// Dial connects to addr through the upstream. Only "tcp" is supported; any
// other network is an error.
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
	dialCtx, cancel := context.WithTimeout(ctx, u.handshakeTimeout())
	defer cancel()
	conn, err := u.DialFunc(dialCtx, network, connectAddr)
	if err != nil {
		return nil, fmt.Errorf("upstream dial %s: %w", connectAddr, err)
	}
	return conn, nil
}
