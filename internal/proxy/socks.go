package proxy

import (
	"context"
	"log/slog"
	"net"

	"github.com/armon/go-socks5"
)

// SOCKSServer is the client facing SOCKS5 proxy. Every client connection is
// dialed through the Upstream, so SOCKS5 traffic also exits via WARP.
type SOCKSServer struct {
	Upstream  *Upstream
	Log       *slog.Logger
	OnRequest func(kind, client, target string)
}

// Serve accepts SOCKS5 connections on ln until it closes.
func (s *SOCKSServer) Serve(ln net.Listener) error {
	conf := &socks5.Config{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return s.Upstream.Dial(ctx, network, addr)
		},
	}
	server, err := socks5.New(conf)
	if err != nil {
		return err
	}
	return server.Serve(ln)
}
