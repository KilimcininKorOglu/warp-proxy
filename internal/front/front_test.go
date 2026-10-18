package front

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"warp-proxy/internal/cleanip"
)

func TestSuffixMatch(t *testing.T) {
	domains := []string{"example.com", "corpx.net"}
	cases := []struct {
		host string
		want bool
	}{
		{"example.com", true},
		{"www.example.com", true},
		{"deep.api.example.com", true},
		{"notexample.com", false},
		{"example.com.evil.test", false},
		{"corpx.net", true},
		{"sub.corpx.net", true},
		{"other.test", false},
	}
	for _, c := range cases {
		if got := suffixMatch(domains, c.host); got != c.want {
			t.Errorf("suffixMatch(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestPickDisabledOrEmptyPool(t *testing.T) {
	s := NewSelector(func() Config {
		return Config{Enabled: true, Domains: []string{"example.com"}}
	})
	if _, changed := s.Pick(context.Background(), "example.com:443"); changed {
		t.Error("fronting applied with an empty pool")
	}

	s.SetPool([]cleanip.Result{{IP: "104.16.1.1", Latency: time.Millisecond}})
	s2 := NewSelector(func() Config { return Config{Enabled: false} })
	s2.SetPool([]cleanip.Result{{IP: "104.16.1.1"}})
	if _, changed := s2.Pick(context.Background(), "example.com:443"); changed {
		t.Error("fronting applied while disabled")
	}
}

func TestPickSuffixListBypassesDetection(t *testing.T) {
	s := NewSelector(func() Config {
		return Config{
			Enabled:         true,
			Domains:         []string{"example.com"},
			ResolveCacheTTL: time.Minute,
		}
	})
	s.SetPool([]cleanip.Result{
		{IP: "104.16.1.1"}, {IP: "104.16.1.2"},
	})

	addr, changed := s.Pick(context.Background(), "www.example.com:443")
	if !changed || addr != "104.16.1.1:443" {
		t.Errorf("addr = %q changed = %v, want pool IP 104.16.1.1", addr, changed)
	}
	// Round-robin: next listed host gets the next pool IP.
	addr, _ = s.Pick(context.Background(), "other.example.com:443")
	if addr != "104.16.1.2:443" {
		t.Errorf("addr = %q, want 104.16.1.2:443", addr)
	}
	// Non-listed, non-CF host passes through untouched.
	if addr, changed := s.Pick(context.Background(), "classic.test:80"); changed || addr != "classic.test:80" {
		t.Errorf("addr = %q changed = %v, want passthrough", addr, changed)
	}
}

func TestPickCacheHits(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		Domains:         []string{"example.com"},
		ResolveCacheTTL: time.Minute,
	}
	s := NewSelector(func() Config { return cfg })
	s.SetPool([]cleanip.Result{{IP: "104.16.1.1"}})

	first, _ := s.Pick(context.Background(), "a.example.com:443")
	second, _ := s.Pick(context.Background(), "a.example.com:443")
	if first != second {
		t.Errorf("cache miss: %q then %q", first, second)
	}
}

func TestPickPassthroughIPLiterals(t *testing.T) {
	s := NewSelector(func() Config {
		return Config{Enabled: true, Domains: []string{"example.com"}, ResolveCacheTTL: time.Minute}
	})
	s.SetPool([]cleanip.Result{{IP: "104.16.1.1"}})
	addr, changed := s.Pick(context.Background(), "104.16.9.9:443")
	if changed || addr != "104.16.9.9:443" {
		t.Errorf("IP literal rewritten: %q changed=%v", addr, changed)
	}
}

func TestSetPoolReplaces(t *testing.T) {
	s := NewSelector(func() Config { return Config{Enabled: true} })
	s.SetPool([]cleanip.Result{{IP: "1.1.1.1"}, {IP: "2.2.2.2"}})
	if s.PoolSize() != 2 {
		t.Fatalf("pool size = %d, want 2", s.PoolSize())
	}
	s.SetPool([]cleanip.Result{{IP: "3.3.3.3"}})
	if s.PoolSize() != 1 {
		t.Errorf("pool size after replace = %d, want 1", s.PoolSize())
	}
}

func TestPickDetectsCloudflareFrontedHost(t *testing.T) {
	// A real HTTP server on loopback is not in Cloudflare ranges, so the
	// automatic check must NOT rewrite it; this exercises the resolver
	// path without touching the network beyond loopback DNS.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	host := srv.URL // http://127.0.0.1:port
	s := NewSelector(func() Config {
		return Config{Enabled: true, ResolveCacheTTL: time.Minute}
	})
	s.SetPool([]cleanip.Result{{IP: "104.16.1.1"}})
	_, changed := s.Pick(context.Background(), host[7:]+":443")
	if changed {
		t.Error("loopback host wrongly marked as Cloudflare-fronted")
	}
}
