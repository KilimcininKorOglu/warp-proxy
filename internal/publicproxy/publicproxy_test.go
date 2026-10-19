package publicproxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseProxyLine(t *testing.T) {
	cases := []struct {
		line string
		ok   bool
		want Candidate
	}{
		{"1.2.3.4:8080", true, Candidate{Scheme: "http", Host: "1.2.3.4", Port: 8080}},
		{"socks5://5.6.7.8:1080", true, Candidate{Scheme: "socks5", Host: "5.6.7.8", Port: 1080}},
		{"SOCKS5://5.6.7.8:1080", true, Candidate{Scheme: "socks5", Host: "5.6.7.8", Port: 1080}},
		{"http://u:p@9.9.9.9:3128", true, Candidate{Scheme: "http", Host: "9.9.9.9", Port: 3128, Username: "u", Password: "p"}},
		// socks4 is dropped at parse time: no stdlib client exists.
		{"socks4://1.1.1.1:1080", false, Candidate{}},
		{"# comment", false, Candidate{}},
		{"", false, Candidate{}},
		{"ftp://1.2.3.4:21", false, Candidate{}},
		{"1.2.3.4", false, Candidate{}},
		{"1.2.3.4:notaport", false, Candidate{}},
		{"1.2.3.4:99999", false, Candidate{}},
		{"host with space:8080", false, Candidate{}},
		{"path://1.2.3.4:80/x", false, Candidate{}},
	}
	for _, tc := range cases {
		c, ok := parseProxyLine(tc.line)
		if ok != tc.ok {
			t.Errorf("parseProxyLine(%q) ok=%v, want %v", tc.line, ok, tc.ok)
			continue
		}
		if ok && c != tc.want {
			t.Errorf("parseProxyLine(%q) = %+v, want %+v", tc.line, c, tc.want)
		}
	}
}

func TestParseProxyLineDefaultsToHTTP(t *testing.T) {
	c, ok := parseProxyLine("  proxy.example.com:3128\n")
	if !ok || c.Scheme != "http" || c.Host != "proxy.example.com" || c.Port != 3128 {
		t.Errorf("parse = %+v ok=%v", c, ok)
	}
}

// proxyServer stands in for an HTTP proxy: the client sends it absolute-form
// requests, it answers with a trace body.
func proxyServer(t *testing.T, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte("fl=x\nip=203.0.113.7\nwarp=on\n"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// serverCandidate returns the test server as an http Candidate.
func serverCandidate(t *testing.T, srv *httptest.Server) Candidate {
	t.Helper()
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	port, _ := strconv.Atoi(portStr)
	return Candidate{Scheme: "http", Host: host, Port: port}
}

func TestCheckVerifiesCandidate(t *testing.T) {
	srv := proxyServer(t, http.StatusOK)
	e, err := Check(context.Background(), serverCandidate(t, srv),
		"http://www.cloudflare.com/cdn-cgi/trace", 5*time.Second)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if e.ExitIP != "203.0.113.7" {
		t.Errorf("exit ip = %q, want 203.0.113.7", e.ExitIP)
	}
	if e.Latency <= 0 {
		t.Error("latency not measured")
	}
	if e.Scheme != "http" || e.Addr == "" {
		t.Errorf("entry incomplete: %+v", e)
	}
}

func TestCheckRejectsBadCandidate(t *testing.T) {
	srv := proxyServer(t, http.StatusForbidden)
	if _, err := Check(context.Background(), serverCandidate(t, srv),
		"http://www.cloudflare.com/cdn-cgi/trace", 5*time.Second); err == nil {
		t.Error("403 candidate accepted")
	}
	// SOCKS4 has no client support and must be rejected up front.
	if _, err := Check(context.Background(), Candidate{Scheme: "socks4", Host: "1.2.3.4", Port: 1080}, "http://x/", time.Second); err == nil {
		t.Error("socks4 candidate accepted")
	}
}

func TestPoolRoundRobin(t *testing.T) {
	p := &Pool{}
	if _, ok := p.Pick(); ok {
		t.Error("empty pool returned an entry")
	}
	p.Set([]Entry{{Addr: "a:1"}, {Addr: "b:2"}, {Addr: "c:3"}})
	seen := map[string]bool{}
	for range 3 {
		e, ok := p.Pick()
		if !ok {
			t.Fatal("pick failed")
		}
		seen[e.Addr] = true
	}
	if len(seen) != 3 {
		t.Errorf("round-robin served %v, want all three", seen)
	}
	if p.Len() != 3 {
		t.Errorf("len = %d, want 3", p.Len())
	}
	if len(p.Snapshot()) != 3 {
		t.Error("snapshot is not a copy")
	}
}

func TestRefreshChecksAndSorts(t *testing.T) {
	srv := proxyServer(t, http.StatusOK)
	host, port, _ := strings.Cut(strings.TrimPrefix(srv.URL, "http://"), ":")
	addr := host + ":" + port
	// Two source lines: one real candidate, one garbage the parser drops,
	// plus a candidate pointing at a closed port that fails the check.
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("# list\nhttp://" + addr + "\n127.0.0.1:1\nnot-a-proxy\n"))
	}))
	t.Cleanup(src.Close)

	p := &Pool{}
	seen, kept := p.Refresh(context.Background(), []string{src.URL},
		"http://www.cloudflare.com/cdn-cgi/trace", 3*time.Second, 10, 10, nil)
	if seen != 2 {
		t.Errorf("seen = %d, want 2 (parseable lines)", seen)
	}
	if kept != 1 {
		t.Fatalf("kept = %d, want 1 (dead candidate must drop)", kept)
	}
	e := p.Snapshot()[0]
	if e.Addr != addr || e.ExitIP != "203.0.113.7" {
		t.Errorf("entry = %+v", e)
	}
	_, last, k, s := p.ScanState()
	if last.IsZero() || k != 1 || s != 2 {
		t.Errorf("scan state = %v %d/%d", last, k, s)
	}
}

func TestRefreshSingleFlight(t *testing.T) {
	p := &Pool{}
	p.BeginScan()
	defer p.EndScan(0, 0)
	seen, kept := p.Refresh(context.Background(), []string{"http://127.0.0.1:1/x"},
		"http://x/", time.Second, 10, 10, nil)
	if seen != 0 || kept != 0 {
		t.Errorf("concurrent refresh ran: %d/%d", seen, kept)
	}
}
