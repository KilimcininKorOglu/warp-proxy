package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

// fakeUpstream is a minimal SOCKS5 proxy standing in for warp-cli.
type fakeUpstream struct{ ln net.Listener }

func newFakeUpstream(t *testing.T) *fakeUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	f := &fakeUpstream{ln: ln}
	go f.serve()
	t.Cleanup(func() { ln.Close() })
	return f
}

func (f *fakeUpstream) serve() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handle(conn)
	}
}

func (f *fakeUpstream) handle(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	// Greeting: VER, NMETHODS, METHODS.
	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil || head[0] != 5 {
		return
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return
	}
	// Request: VER CMD RSV ATYP ADDR PORT.
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil || req[1] != 1 {
		return
	}
	var host string
	switch req[3] {
	case 1:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(br, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(br, l); err != nil {
			return
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(br, name); err != nil {
			return
		}
		host = string(name)
	case 4:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(br, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	default:
		return
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(br, port); err != nil {
		return
	}
	target, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port)))))
	if err != nil {
		conn.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0}) // host unreachable
		return
	}
	defer target.Close()
	conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}) // success
	done := make(chan struct{}, 2)
	go func() { io.Copy(target, br); done <- struct{}{} }()
	go func() { io.Copy(conn, target); done <- struct{}{} }()
	<-done
}

func startHTTPProxy(t *testing.T, up *Upstream) (addr string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen http proxy: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	srv := &http.Server{Handler: &HTTPServer{Upstream: up}}
	go srv.Serve(ln)
	return ln.Addr().String()
}

func startSOCKSProxy(t *testing.T, up *Upstream) (addr string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen socks proxy: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &SOCKSServer{Upstream: up}
	go s.Serve(ln)
	return ln.Addr().String()
}

func TestHTTPProxyConnectThroughUpstream(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello-via-warp")
	}))
	defer target.Close()

	up := newFakeUpstream(t)
	addr := startHTTPProxy(t, &Upstream{Addr: up.ln.Addr().String()})

	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   10 * time.Second,
	}
	resp, err := client.Get(target.URL + "/path")
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello-via-warp" {
		t.Errorf("body = %q, want hello-via-warp", body)
	}
}

func TestHTTPProxyPlainForward(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "plain-ok")
	}))
	defer target.Close()

	up := newFakeUpstream(t)
	addr := startHTTPProxy(t, &Upstream{Addr: up.ln.Addr().String()})

	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   10 * time.Second,
	}
	req, _ := http.NewRequest("GET", "http://"+strings.TrimPrefix(target.URL, "http://")+"/x", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("plain GET via proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "plain-ok" {
		t.Errorf("body = %q, want plain-ok", body)
	}
}

func TestSOCKSProxyThroughUpstream(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "socks-ok")
	}))
	defer target.Close()

	up := newFakeUpstream(t)
	socksAddr := startSOCKSProxy(t, &Upstream{Addr: up.ln.Addr().String()})

	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("SOCKS5 dialer: %v", err)
	}
	tURL, _ := url.Parse(target.URL)
	conn, err := dialer.Dial("tcp", tURL.Host)
	if err != nil {
		t.Fatalf("socks dial: %v", err)
	}
	defer conn.Close()

	req, _ := http.NewRequest("GET", target.URL, nil)
	if err := req.Write(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "socks-ok" {
		t.Errorf("body = %q, want socks-ok", body)
	}
}

func TestUpstreamRefusedConnectReturnsError(t *testing.T) {
	// A listener that accepts the greeting but rejects every method stands
	// in for an upstream that refuses the tunnel.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 64)
			conn.Read(buf)
			conn.Write([]byte{5, 0xFF}) // no acceptable methods
			conn.Close()
		}
	}()

	u := &Upstream{Addr: ln.Addr().String(), Timeout: 5 * time.Second}
	_, err = u.Dial(context.Background(), "tcp", "example.com:443")
	if err == nil {
		t.Fatal("Dial succeeded against a refusing upstream")
	}
}
