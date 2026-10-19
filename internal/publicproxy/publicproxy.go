// Package publicproxy keeps a live pool of public proxies scraped from
// published lists: it fetches the sources, verifies every candidate with a
// real request and stores the survivors sorted by latency. The bridge uses
// the pool as a fallback exit when the WARP retries are exhausted.
package publicproxy

import (
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Entry is one verified public proxy.
type Entry struct {
	Scheme    string        // http, https, socks5, socks5h
	Addr      string        // "host:port"
	Latency   time.Duration // full request round trip through the proxy
	ExitIP    string        // the address the target saw, when check_url reports one
	CheckedAt time.Time
}

// URL renders the entry as a proxy URL for http.Transport.
func (e Entry) URL() string {
	return e.Scheme + "://" + e.Addr
}

// Pool is the concurrency-safe set of verified proxies.
type Pool struct {
	mu      sync.RWMutex
	entries []Entry
	next    atomic.Uint64

	scanning atomic.Bool
	lastScan time.Time
	lastKept int
	lastSeen int
}

// Set replaces the pool with the verified entries (already sorted).
func (p *Pool) Set(entries []Entry) {
	p.mu.Lock()
	p.entries = entries
	p.mu.Unlock()
}

// Pick returns the next entry in round-robin order.
func (p *Pool) Pick() (Entry, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.entries) == 0 {
		return Entry{}, false
	}
	i := int(p.next.Add(1)-1) % len(p.entries) // #nosec G115 -- 64-bit counter, overflow unreachable
	return p.entries[i], true
}

// Snapshot returns a copy of the verified entries.
func (p *Pool) Snapshot() []Entry {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]Entry(nil), p.entries...)
}

// Len reports the pool size.
func (p *Pool) Len() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.entries)
}

// BeginScan claims the scan slot; false means a scan already runs.
func (p *Pool) BeginScan() bool {
	return !p.scanning.Swap(true)
}

// EndScan records the scan outcome and releases the slot.
func (p *Pool) EndScan(kept, seen int) {
	p.mu.Lock()
	p.lastScan = time.Now()
	p.lastKept = kept
	p.lastSeen = seen
	p.mu.Unlock()
	p.scanning.Store(false)
}

// ScanState reports the last scan outcome and whether one runs now.
func (p *Pool) ScanState() (running bool, last time.Time, kept, seen int) {
	return p.scanning.Load(), p.lastScan, p.lastKept, p.lastSeen
}

// Transport builds an HTTP transport that exits through the pool's next
// proxy, or nil when the pool is empty.
func (p *Pool) Transport() *http.Transport {
	e, ok := p.Pick()
	if !ok {
		return nil
	}
	u, err := parseProxyURL(e.URL())
	if err != nil {
		return nil
	}
	return &http.Transport{Proxy: http.ProxyURL(u)}
}
