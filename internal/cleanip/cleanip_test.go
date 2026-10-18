package cleanip

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCandidatesSpreadsAcrossRange(t *testing.T) {
	ips, err := Candidates([]string{"104.16.0.0/12"}, 4)
	if err != nil {
		t.Fatalf("Candidates: %v", err)
	}
	if len(ips) != 4 {
		t.Fatalf("len = %d, want 4", len(ips))
	}
	seen := map[string]bool{}
	for _, ip := range ips {
		if net.ParseIP(ip) == nil {
			t.Errorf("invalid IP %q", ip)
		}
		if seen[ip] {
			t.Errorf("duplicate candidate %q", ip)
		}
		seen[ip] = true
	}
}

func TestCandidatesStaysInsideSmallRange(t *testing.T) {
	// A /32 holds one address; n larger than the range must not overflow.
	ips, err := Candidates([]string{"1.2.3.4/32"}, 4)
	if err != nil {
		t.Fatalf("Candidates: %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("no candidate from /32")
	}
	for _, ip := range ips {
		if ip != "1.2.3.4" {
			t.Errorf("candidate %q outside the /32", ip)
		}
	}
}

func TestCandidatesRejectsBadRange(t *testing.T) {
	if _, err := Candidates([]string{"not-a-cidr"}, 1); err == nil {
		t.Error("bad CIDR accepted")
	}
}

func TestScanKeepsOnlyReachableSortedByLatency(t *testing.T) {
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer fast.Close()
	port := portOf(t, fast.URL)

	// 127.0.0.2 has no listener on this port, so only the fast candidate
	// survives the scan.
	results := Scan(context.Background(), Params{
		Port:            port,
		SamplesPerRange: 1,
		Workers:         4,
		Timeout:         time.Second,
	}, []string{"127.0.0.1/32", "127.0.0.2/32"})

	if len(results) != 1 {
		t.Fatalf("results = %+v, want only 127.0.0.1", results)
	}
	if results[0].IP != "127.0.0.1" {
		t.Errorf("IP = %q, want 127.0.0.1", results[0].IP)
	}
	if results[0].Latency <= 0 || results[0].Latency > time.Second {
		t.Errorf("latency = %v, want a positive sub-timeout measure", results[0].Latency)
	}
}

func TestScanTopTruncates(t *testing.T) {
	// Same /24 sampled twice gives two candidates on one port; only the
	// listening address comes back, so use Top on a single result list.
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer fast.Close()
	port := portOf(t, fast.URL)

	results := Scan(context.Background(), Params{
		Port:            port,
		SamplesPerRange: 2,
		Workers:         4,
		Timeout:         time.Second,
		Top:             1,
	}, []string{"127.0.0.1/32"})
	if len(results) > 1 {
		t.Errorf("Top=1 returned %d results", len(results))
	}
}

func TestProbeReportsFailure(t *testing.T) {
	// Port 1 on loopback has no listener in CI containers.
	if _, err := Probe(context.Background(), "127.0.0.1", 1, 500*time.Millisecond); err == nil {
		t.Error("probe succeeded against a closed port")
	}
}

func portOf(t *testing.T, url string) int {
	t.Helper()
	var port int
	if _, err := fmt.Sscanf(url, "http://127.0.0.1:%d", &port); err != nil || port == 0 {
		t.Fatalf("no port in %q: %v", url, err)
	}
	return port
}
