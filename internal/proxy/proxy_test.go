package proxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

// fakeDialUpstream returns an Upstream whose DialFunc dials the given
// listener directly, standing in for the tunnel's netstack.
func fakeDialUpstream(t *testing.T, ln net.Listener) *Upstream {
	t.Helper()
	return &Upstream{
		DialFunc: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, ln.Addr().String())
		},
	}
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

	tURL, _ := url.Parse(target.URL)
	up := fakeDialUpstream(t, mustDial(t, tURL.Host))
	addr := startHTTPProxy(t, up)

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

	tURL, _ := url.Parse(target.URL)
	up := fakeDialUpstream(t, mustDial(t, tURL.Host))
	addr := startHTTPProxy(t, up)

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

	tURL, _ := url.Parse(target.URL)
	up := fakeDialUpstream(t, mustDial(t, tURL.Host))
	socksAddr := startSOCKSProxy(t, up)

	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("SOCKS5 dialer: %v", err)
	}
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

func TestUpstreamDialFailureReturnsError(t *testing.T) {
	// A closed listener stands in for an unreachable tunnel target.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	closed := ln.Addr().String()
	ln.Close()

	up := &Upstream{
		DialFunc: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, closed)
		},
		Timeout: 3 * time.Second,
	}
	if _, err := up.Dial(context.Background(), "tcp", "example.com:443"); err == nil {
		t.Fatal("Dial succeeded against a dead target")
	}
}

func TestUpstreamRejectsNonTCP(t *testing.T) {
	up := &Upstream{DialFunc: func(context.Context, string, string) (net.Conn, error) {
		return nil, nil
	}}
	if _, err := up.Dial(context.Background(), "udp", "example.com:53"); err == nil {
		t.Error("udp dial accepted")
	}
}

func mustDial(t *testing.T, hostPort string) net.Listener {
	t.Helper()
	dialLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen relay: %v", err)
	}
	t.Cleanup(func() { dialLn.Close() })
	// Relay every accepted connection to the target host.
	go func() {
		for {
			src, err := dialLn.Accept()
			if err != nil {
				return
			}
			go func(src net.Conn) {
				dst, err := net.Dial("tcp", hostPort)
				if err != nil {
					src.Close()
					return
				}
				done := make(chan struct{}, 2)
				go func() { io.Copy(dst, src); done <- struct{}{} }()
				go func() { io.Copy(src, dst); done <- struct{}{} }()
				<-done
				src.Close()
				dst.Close()
			}(src)
		}
	}()
	return dialLn
}
