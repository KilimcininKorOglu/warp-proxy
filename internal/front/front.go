// Package front rewrites target hosts to fast Cloudflare "front" edge IPs.
// A front IP only works for Cloudflare-fronted sites: TLS SNI still routes
// the request, but the TCP connection lands on a measured-fast edge. Two
// triggers enable the rewrite for a host: an explicit domain suffix list
// and automatic detection that the host resolves inside Cloudflare's
// official ranges.
package front

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"warp-proxy/internal/cleanip"
)

// Config controls the selector. Updated live from the panel.
type Config struct {
	Enabled         bool
	Domains         []string
	ResolveCacheTTL time.Duration
}

// Selector decides per host whether to use a front IP and which one.
type Selector struct {
	cfg func() Config

	mu            sync.Mutex
	pool          []string // front IPs, newest scan first
	next          int      // round-robin index into pool
	ranges        []*net.IPNet
	rangesFetched time.Time

	// decision cache: host -> front IP to use ("" means no fronting)
	cacheMu sync.Mutex
	cache   map[string]cacheEntry
}

type cacheEntry struct {
	ip      string
	expires time.Time
}

// NewSelector builds a Selector. cfg is read on every decision so panel
// edits apply immediately.
func NewSelector(cfg func() Config) *Selector {
	return &Selector{cfg: cfg, cache: make(map[string]cacheEntry)}
}

// SetPool replaces the front IP pool with the given scan results.
func (s *Selector) SetPool(results []cleanip.Result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pool = s.pool[:0]
	for _, r := range results {
		s.pool = append(s.pool, r.IP)
	}
	s.next = 0
}

// PoolSize reports the current front pool size.
func (s *Selector) PoolSize() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pool)
}

// Pick returns the address to connect to for hostPort ("host:port").
// When fronting applies, host is replaced by a pool IP and (ok=true).
// The decision is cached per host for the configured TTL.
func (s *Selector) Pick(ctx context.Context, hostPort string) (string, bool) {
	cfg := s.cfg()
	if !cfg.Enabled || s.PoolSize() == 0 {
		return hostPort, false
	}
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil || net.ParseIP(host) != nil {
		// Malformed or already an IP literal: pass through untouched.
		return hostPort, false
	}

	if ip, ok := s.cached(cfg, host); ok {
		return join(ip, port), ip != ""
	}

	ip := s.decide(ctx, cfg, host)
	s.store(cfg, host, ip)
	if ip == "" {
		return hostPort, false
	}
	return join(ip, port), true
}

// decide resolves the host and returns a front IP when the suffix list or
// the Cloudflare range check says so. "" means no fronting.
func (s *Selector) decide(ctx context.Context, cfg Config, host string) string {
	if suffixMatch(cfg.Domains, host) {
		return s.nextIP()
	}
	inCF, err := s.inCloudflareRanges(ctx, host)
	if err != nil {
		// Detection unavailable: fall back to list-only decisions.
		return ""
	}
	if inCF {
		return s.nextIP()
	}
	return ""
}

// suffixMatch reports whether host equals or ends at one of the listed
// suffixes ("example.com" matches www.example.com).
func suffixMatch(domains []string, host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if host == d || strings.HasSuffix(host, "."+strings.TrimPrefix(d, ".")) {
			return true
		}
	}
	return false
}

// nextIP returns the next pool IP in round-robin order.
func (s *Selector) nextIP() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pool) == 0 {
		return ""
	}
	ip := s.pool[s.next%len(s.pool)]
	s.next++
	return ip
}

// inCloudflareRanges resolves the host and reports whether any address
// falls inside Cloudflare's official IPv4 ranges. The range list is
// fetched at most once per day.
func (s *Selector) inCloudflareRanges(ctx context.Context, host string) (bool, error) {
	if err := s.refreshRanges(ctx); err != nil {
		return false, err
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return false, err
	}
	s.mu.Lock()
	ranges := s.ranges
	s.mu.Unlock()
	for _, addr := range addresses {
		ip4 := addr.IP.To4()
		if ip4 == nil {
			continue
		}
		for _, n := range ranges {
			if n.Contains(ip4) {
				return true, nil
			}
		}
	}
	return false, nil
}

// refreshRanges downloads the official range list when stale.
func (s *Selector) refreshRanges(ctx context.Context) error {
	s.mu.Lock()
	fresh := !s.rangesFetched.IsZero() && time.Since(s.rangesFetched) < 24*time.Hour
	s.mu.Unlock()
	if fresh {
		return nil
	}

	raw, err := cleanip.FetchRanges(ctx)
	if err != nil {
		return err
	}
	var parsed []*net.IPNet
	for _, cidr := range raw {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		parsed = append(parsed, ipnet)
	}
	s.mu.Lock()
	s.ranges = parsed
	s.rangesFetched = time.Now()
	s.mu.Unlock()
	return nil
}

// cached returns the cached decision when it is still valid. The second
// result is false when no valid entry exists.
func (s *Selector) cached(cfg Config, host string) (string, bool) {
	if cfg.ResolveCacheTTL <= 0 {
		return "", false
	}
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	e, ok := s.cache[host]
	if !ok || time.Now().After(e.expires) {
		return "", false
	}
	return e.ip, true
}

func (s *Selector) store(cfg Config, host, ip string) {
	if cfg.ResolveCacheTTL <= 0 {
		return
	}
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	// Bound the cache so a long-running instance cannot grow without
	// limit; 4096 hosts is far above realistic panel traffic.
	if len(s.cache) > 4096 {
		s.cache = make(map[string]cacheEntry)
	}
	s.cache[host] = cacheEntry{ip: ip, expires: time.Now().Add(cfg.ResolveCacheTTL)}
}

func join(ip, port string) string {
	if ip == "" {
		return ""
	}
	return net.JoinHostPort(ip, port)
}
