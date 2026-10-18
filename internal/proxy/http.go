package proxy

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// HTTPServer is the client facing HTTP/1.1 proxy. CONNECT and plain
// requests are both forwarded through the Upstream.
type HTTPServer struct {
	Upstream *Upstream
	Log      *slog.Logger
	// OnRequest is called for every accepted client request.
	OnRequest func(kind, client, target string)
}

// Serve accepts connections on ln until it closes.
func (s *HTTPServer) Serve(ln net.Listener) error {
	srv := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 30 * time.Second,
	}
	return srv.Serve(ln)
}

func (s *HTTPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	client := clientAddr(r.RemoteAddr)
	if r.Method == http.MethodConnect {
		s.serveConnect(w, r, client)
		return
	}
	s.serveForward(w, r, client)
}

// serveConnect tunnels an HTTPS CONNECT request through the upstream.
func (s *HTTPServer) serveConnect(w http.ResponseWriter, r *http.Request, client string) {
	s.noteRequest("connect", client, r.Host)

	upConn, err := s.Upstream.Dial(r.Context(), "tcp", r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		upConn.Close()
		http.Error(w, "connection hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, rw, err := hj.Hijack()
	if err != nil {
		upConn.Close()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// The 200 response must go through rw because Hijack may expose an
	// already buffered writer.
	if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		clientConn.Close()
		upConn.Close()
		return
	}
	if err := rw.Flush(); err != nil {
		clientConn.Close()
		upConn.Close()
		return
	}
	go tunnel(clientConn, upConn)
}

// tunnel copies both directions between client and upstream until one side
// closes, then closes both.
func tunnel(client, upstream net.Conn) {
	defer client.Close()
	defer upstream.Close()
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(client, upstream)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(upstream, client)
		done <- struct{}{}
	}()
	<-done
}

// serveForward proxies a plain (absolute-form) HTTP request.
func (s *HTTPServer) serveForward(w http.ResponseWriter, r *http.Request, client string) {
	s.noteRequest("http", client, r.Host)

	transport := &http.Transport{
		DialContext:           s.Upstream.Dial,
		Proxy:                 nil,
		ResponseHeaderTimeout: s.Upstream.handshakeTimeout(),
		IdleConnTimeout:       60 * time.Second,
	}
	resp, err := transport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (s *HTTPServer) noteRequest(kind, client, target string) {
	if s.OnRequest != nil {
		s.OnRequest(kind, client, target)
	}
	if s.Log != nil {
		s.Log.Info("proxy request", "kind", kind, "client", client, "target", target)
	}
}

func copyHeader(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func clientAddr(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return remote
	}
	return host
}
