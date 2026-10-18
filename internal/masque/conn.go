package masque

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/waiter"
)

// readBufSize is the internal read buffer: gVisor's Endpoint.Read demands an
// io.Writer that consumes the whole segment, so reads go through an
// intermediate buffer and are served to the caller in p-sized pieces.
const readBufSize = 65535

// endpointConn adapts a connected gVisor TCP endpoint to net.Conn with
// blocking reads and writes. A deadline expiry aborts the connection: the
// tunnel has no use for a usable-after-timeout socket, and gVisor endpoints
// carry no per-operation deadlines.
type endpointConn struct {
	ep tcpip.Endpoint
	wq *waiter.Queue

	local  *net.TCPAddr
	remote *net.TCPAddr

	mu            sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
	pend          []byte // received bytes not yet handed to the caller
}

// wait blocks until the endpoint signals the mask, the context ends, or the
// deadline expires.
func (c *endpointConn) wait(mask waiter.EventMask, ctx context.Context, deadline time.Time) error {
	entry, ch := waiter.NewChannelEntry(mask | waiter.EventErr | waiter.EventHUp)
	c.wq.EventRegister(&entry)
	defer c.wq.EventUnregister(&entry)
	var timerC <-chan time.Time
	if !deadline.IsZero() {
		d := time.Until(deadline)
		if d <= 0 {
			return &errTimeout{}
		}
		timer := time.NewTimer(d)
		defer timer.Stop()
		timerC = timer.C
	}
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		c.ep.Abort()
		return ctx.Err()
	case <-timerC:
		c.ep.Abort()
		return &errTimeout{}
	}
}

// errTimeout marks a deadline expiry, mirroring net's timeout error shape.
type errTimeout struct{}

func (errTimeout) Error() string   { return "i/o timeout" }
func (errTimeout) Timeout() bool   { return true }
func (errTimeout) Temporary() bool { return true }

// Read implements net.Conn.
func (c *endpointConn) Read(p []byte) (int, error) {
	for {
		if len(c.pend) > 0 {
			n := copy(p, c.pend)
			c.pend = c.pend[n:]
			return n, nil
		}
		if len(p) == 0 {
			return 0, nil
		}
		buf := make([]byte, readBufSize)
		res, err := c.ep.Read(&bytesSliceWriter{p: buf}, tcpip.ReadOptions{})
		if err == nil {
			c.pend = buf[:res.Count]
			continue
		}
		if isEOF(err) {
			return 0, io.EOF
		}
		if !isWouldBlock(err) {
			return 0, mapEpErr(err)
		}
		c.mu.Lock()
		deadline := c.readDeadline
		c.mu.Unlock()
		if werr := c.wait(waiter.ReadableEvents, context.Background(), deadline); werr != nil {
			return 0, werr
		}
	}
}

// isEOF reports whether the gVisor error means the stream is over.
func isEOF(err tcpip.Error) bool {
	switch err.(type) {
	case *tcpip.ErrClosedForReceive, *tcpip.ErrClosedForSend, *tcpip.ErrNotConnected:
		return true
	}
	return false
}

// Write implements net.Conn.
func (c *endpointConn) Write(p []byte) (int, error) {
	rd := bytes.NewReader(p)
	for {
		n, err := c.ep.Write(rd, tcpip.WriteOptions{})
		if err == nil {
			return int(n), nil
		}
		if !isWouldBlock(err) {
			return int(n), mapEpErr(err)
		}
		c.mu.Lock()
		deadline := c.writeDeadline
		c.mu.Unlock()
		if werr := c.wait(waiter.WritableEvents, context.Background(), deadline); werr != nil {
			return int(n), werr
		}
	}
}

// Close implements net.Conn.
func (c *endpointConn) Close() error {
	c.ep.Close()
	return nil
}

// LocalAddr implements net.Conn: the tunnel-assigned address.
func (c *endpointConn) LocalAddr() net.Addr { return c.local }

// RemoteAddr implements net.Conn: the dialed target.
func (c *endpointConn) RemoteAddr() net.Addr { return c.remote }

// SetDeadline implements net.Conn.
func (c *endpointConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline, c.writeDeadline = t, t
	c.mu.Unlock()
	return nil
}

// SetReadDeadline implements net.Conn.
func (c *endpointConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	return nil
}

// SetWriteDeadline implements net.Conn.
func (c *endpointConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}

// mapEpErr converts a gVisor error into a Go error.
func mapEpErr(err tcpip.Error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("tunnel endpoint: %s", err.String())
}

// bytesSliceWriter adapts a []byte to the io.Writer Endpoint.Read fills.
type bytesSliceWriter struct{ p []byte }

var _ io.Writer = (*bytesSliceWriter)(nil)

func (w *bytesSliceWriter) Write(b []byte) (int, error) {
	n := copy(w.p, b)
	w.p = w.p[n:]
	return n, nil
}
