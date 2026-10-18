package bridge

import (
	"context"
	"io"
	"log/slog"
	"net"

	"warp-proxy/internal/proxy"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// dialUpstream returns an Upstream whose dialer connects straight to the
// given host:port, standing in for the tunnel's netstack.
func dialUpstream(hostPort string) *proxy.Upstream {
	return &proxy.Upstream{
		DialFunc: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, hostPort)
		},
	}
}
