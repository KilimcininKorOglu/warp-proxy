package masque

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// capsuleConnectIPData is the CONNECT-IP DATA capsule (RFC 9484): its value
// is one full IP packet.
const capsuleConnectIPData = 0x00

// h2ConnectTimeout bounds the TCP dial, the TLS handshake and the CONNECT
// round trip.
const h2ConnectTimeout = 15 * time.Second

// h2Debug logs tunnel traffic when MASQUE_DEBUG=1.
func h2Debug(format string, args ...any) {
	if os.Getenv("MASQUE_DEBUG") == "1" {
		log.Printf("masque: "+format, args...)
	}
}

// http2DefaultWindowSize is the RFC 7540 initial flow-control window.
const http2DefaultWindowSize = 65535

// h2StreamID is the single CONNECT stream of the tunnel.
const h2StreamID = 1

// maxCapsuleLen bounds a capsule's declared length so a hostile peer cannot
// make the session preallocate unbounded memory. IP packets stay far below.
const maxCapsuleLen = 1 << 20

// dialH2 establishes the MASQUE session over the HTTP/2 fallback: TCP+TLS to
// the H2 endpoint, then a plain CONNECT carrying the cf-connect-proto header.
// The endpoint never advertises ENABLE_CONNECT_PROTOCOL, so a stock HTTP/2
// client refuses to send :protocol; the session is therefore driven manually
// over the frame layer, mirroring the reference client. IP packets travel as
// CONNECT-IP DATA capsules on the CONNECT stream.
func dialH2(ctx context.Context, id *Identity, conf *tls.Config) (*Tunnel, error) {
	addr := net.JoinHostPort(id.EndpointH2V4, "443")
	dialer := &net.Dialer{Timeout: h2ConnectTimeout}
	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial %s: %w", addr, err)
	}
	tlsConf := conf.Clone()
	tlsConf.NextProtos = []string{"h2"}
	tc := tls.Client(raw, tlsConf)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("tls handshake %s: %w", addr, err)
	}
	sess, err := newH2Session(tc)
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("h2 session: %w", err)
	}
	sess.wg.Add(1)
	go sess.readLoop()

	status, err := sess.connect(ctx)
	if err != nil {
		_ = sess.close()
		return nil, err
	}
	return &Tunnel{
		send:   sess.sendIP,
		recv:   sess.recvIP,
		closer: sess.close,
		status: status,
	}, nil
}

// h2Session is one HTTP/2 connection carrying one CONNECT stream.
type h2Session struct {
	conn *tls.Conn
	fr   *http2.Framer
	dec  *hpack.Decoder

	// outbound flow control: bytes the peer's window still allows.
	mu          sync.Mutex
	peerWindow  int64
	windowReady chan struct{} // closed on the first WINDOW_UPDATE
	statusCh    chan int
	readErr     error

	// inbound capsule stream assembled from DATA frames.
	dataCh chan []byte

	wg     sync.WaitGroup
	closed bool
}

func newH2Session(tc *tls.Conn) (*h2Session, error) {
	s := &h2Session{
		conn:        tc,
		fr:          http2.NewFramer(bufio.NewWriter(tc), tc),
		peerWindow:  http2DefaultWindowSize,
		windowReady: make(chan struct{}),
		statusCh:    make(chan int, 1),
		dataCh:      make(chan []byte, 64),
	}
	s.dec = hpack.NewDecoder(4096, func(hf hpack.HeaderField) {})
	// The client preface and its SETTINGS open the connection.
	if _, err := s.conn.Write([]byte(http2.ClientPreface)); err != nil {
		return nil, err
	}
	if err := s.fr.WriteSettings(); err != nil {
		return nil, err
	}
	return s, nil
}

// connect sends the extended CONNECT and waits for the :status answer.
func (s *h2Session) connect(ctx context.Context) (int, error) {
	var hb hpackEncoder
	// ConnectURI is "https://<host>"; its host is the :authority.
	authority := strings.TrimPrefix(ConnectURI, "https://")
	hb.field(":method", http.MethodConnect)
	hb.field(":scheme", "https")
	hb.field(":authority", authority)
	hb.field(":path", "/")
	hb.field(":protocol", ConnectProtocol)
	hb.field("cf-connect-proto", ConnectProtocol)
	hb.field("capsule-protocol", "?1")
	hb.field("pq-enabled", "false")
	hb.field("user-agent", "")
	if err := s.fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      h2StreamID,
		EndHeaders:    true,
		EndStream:     false,
		BlockFragment: hb.bytes(),
	}); err != nil {
		return 0, fmt.Errorf("send CONNECT: %w", err)
	}
	select {
	case status := <-s.statusCh:
		return status, nil
	case <-ctx.Done():
		return 0, fmt.Errorf("CONNECT: %w", ctx.Err())
	case <-time.After(h2ConnectTimeout):
		return 0, fmt.Errorf("CONNECT: no answer within %s", h2ConnectTimeout)
	}
}

// readLoop consumes frames until the connection dies. It answers SETTINGS,
// tracks the outbound window, feeds the capsule stream and delivers the
// CONNECT :status.
func (s *h2Session) readLoop() {
	defer s.wg.Done()
	defer close(s.dataCh)
	for {
		f, err := s.fr.ReadFrame()
		if err != nil {
			h2Debug("read error: %v", err)
			s.mu.Lock()
			s.readErr = err
			s.mu.Unlock()
			return
		}
		h2Debug("read frame: %T %v", f, f.Header())
		if s.handleFrame(f) {
			return
		}
	}
}

// handleFrame dispatches one read frame. It returns true when the loop
// must stop (GOAWAY).
func (s *h2Session) handleFrame(f http2.Frame) bool {
	switch f := f.(type) {
	case *http2.SettingsFrame:
		s.handleSettings(f)
	case *http2.WindowUpdateFrame:
		s.mu.Lock()
		s.peerWindow += int64(f.Increment)
		s.mu.Unlock()
		select {
		case <-s.windowReady:
		default:
			close(s.windowReady)
		}
	case *http2.HeadersFrame:
		s.handleHeaders(f)
	case *http2.DataFrame:
		s.handleData(f)
	case *http2.PingFrame:
		if !f.IsAck() {
			_ = s.fr.WritePing(true, f.Data)
		}
	case *http2.GoAwayFrame:
		s.mu.Lock()
		s.readErr = fmt.Errorf("server GOAWAY: %s", f.ErrCode)
		s.mu.Unlock()
		return true
	}
	return false
}

// handleSettings answers a peer SETTINGS frame and tracks the initial
// window size.
func (s *h2Session) handleSettings(f *http2.SettingsFrame) {
	if f.IsAck() {
		return
	}
	_ = f.ForeachSetting(func(st http2.Setting) error {
		if st.ID == http2.SettingInitialWindowSize {
			s.mu.Lock()
			s.peerWindow = int64(st.Val)
			s.mu.Unlock()
		}
		return nil
	})
	_ = s.fr.WriteSettingsAck()
}

// handleHeaders decodes the CONNECT response's :status header.
func (s *h2Session) handleHeaders(f *http2.HeadersFrame) {
	s.dec.SetEmitFunc(func(hf hpack.HeaderField) {
		if hf.Name == ":status" && len(s.statusCh) == 0 {
			var status int
			_, _ = fmt.Sscanf(hf.Value, "%d", &status)
			s.statusCh <- status
		}
	})
	_, _ = s.dec.Write(f.HeaderBlockFragment())
	if f.HeadersEnded() {
		s.dec.SetEmitFunc(func(hpack.HeaderField) {})
	}
}

// handleData feeds tunnel data downstream, returning flow-control credit
// immediately: the capsule reader applies its own backpressure by blocking
// on the channel.
func (s *h2Session) handleData(f *http2.DataFrame) {
	if f.StreamID != h2StreamID {
		return
	}
	_ = s.fr.WriteWindowUpdate(0, uint32(f.Length))
	_ = s.fr.WriteWindowUpdate(f.StreamID, uint32(f.Length))
	select {
	case s.dataCh <- f.Data():
	default: // drop when the consumer fell behind; packet loss is
		// survivable above the IP layer
	}
}

// capsuleFrame frames one IP packet as a CONNECT-IP DATA capsule:
// varint(type 0) || varint(len) || packet.
func capsuleFrame(packet []byte) []byte {
	buf := quicvarint.Append(nil, capsuleConnectIPData)
	buf = quicvarint.Append(buf, uint64(len(packet)))
	return append(buf, packet...)
}

// sendIP writes one IP packet as a CONNECT-IP DATA capsule, honoring the
// peer's flow-control window.
func (s *h2Session) sendIP(packet []byte) error {
	frame := capsuleFrame(packet)
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return net.ErrClosed
		}
		if s.peerWindow >= int64(len(frame)) {
			s.peerWindow -= int64(len(frame))
			s.mu.Unlock()
			return s.fr.WriteData(h2StreamID, false, frame)
		}
		s.mu.Unlock()
		select {
		case <-s.windowReady:
		case <-time.After(10 * time.Second):
			return fmt.Errorf("flow control: no window update within 10s")
		}
	}
}

// recvIP returns the next CONNECT-IP DATA capsule payload (an IP packet),
// assembling capsules that span DATA frames.
func (s *h2Session) recvIP(ctx context.Context) ([]byte, error) {
	cr := &capsuleReader{}
	for {
		if pkt, ok := cr.next(); ok {
			if cr.typ == capsuleConnectIPData {
				return pkt, nil
			}
		}
		select {
		case b, ok := <-s.dataCh:
			if !ok {
				s.mu.Lock()
				err := s.readErr
				s.mu.Unlock()
				if err == nil {
					err = io.EOF
				}
				return nil, err
			}
			cr.push(b)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// capsuleReader is a streaming parser for the CONNECT-IP capsule stream.
type capsuleReader struct {
	buf     []byte
	typ     uint64
	haveTyp bool
	want    int    // bytes still needed for the current value; -1 = need length
	value   []byte // accumulated value bytes
}

func (cr *capsuleReader) push(b []byte) { cr.buf = append(cr.buf, b...) }

// next completes one capsule if the buffered bytes suffice and reports it.
func (cr *capsuleReader) next() ([]byte, bool) {
	for {
		if cr.want < 0 { // reading the length varint
			v, n, err := quicvarint.Parse(cr.buf)
			if err != nil {
				return nil, false
			}
			cr.buf = cr.buf[n:]
			// A hostile peer must not make us preallocate gigabytes.
			if v > maxCapsuleLen {
				return nil, false
			}
			cr.want = int(v) // #nosec G115 -- bounded by maxCapsuleLen above
			cr.value = make([]byte, 0, cr.want)
			continue
		}
		if cr.want > 0 {
			take := min(len(cr.buf), cr.want)
			cr.value = append(cr.value, cr.buf[:take]...)
			cr.buf = cr.buf[take:]
			cr.want -= take
			if cr.want > 0 {
				return nil, false
			}
		}
		if !cr.haveTyp { // reading the type varint
			v, n, err := quicvarint.Parse(cr.buf)
			if err != nil {
				return nil, false
			}
			cr.buf = cr.buf[n:]
			cr.typ = v
			cr.haveTyp = true
			cr.want = -1
			continue
		}
		out := cr.value
		cr.haveTyp = false
		cr.want = 0
		cr.value = nil
		return out, true
	}
}

func (s *h2Session) close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	// RST_STREAM ends the CONNECT stream; the TCP close ends the session.
	_ = s.fr.WriteRSTStream(h2StreamID, http2.ErrCodeNo)
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	_ = s.conn.SetReadDeadline(time.Now().Add(time.Second))
	<-done
	return s.conn.Close()
}

// hpackEncoder accumulates header fields and encodes them with a throwaway
// HPACK encoder (each CONNECT is the only request on the stream).
type hpackEncoder struct {
	fields []hpack.HeaderField
}

func (he *hpackEncoder) field(name, value string) {
	he.fields = append(he.fields, hpack.HeaderField{Name: name, Value: value})
}

func (he *hpackEncoder) bytes() []byte {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	for _, f := range he.fields {
		_ = enc.WriteField(f)
	}
	return buf.Bytes()
}
