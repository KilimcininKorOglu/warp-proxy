package publicproxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// Check sends one real request through the candidate and, on success,
// returns a verified Entry with latency and the exit IP the target saw.
// Every candidate must fetch check_url in full: proxies that accept the
// connection and then stall are dropped, not merely slow. SOCKS4 has no
// stdlib client and is rejected.
func Check(ctx context.Context, c Candidate, checkURL string,
	timeout time.Duration) (Entry, error) {
	if c.Scheme == "socks4" {
		return Entry{}, fmt.Errorf("socks4 has no client support")
	}
	proxyURL, err := parseProxyURL(c.Key())
	if err != nil {
		return Entry{}, err
	}
	if c.Username != "" {
		proxyURL.User = url.UserPassword(c.Username, c.Password)
	}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, checkURL, nil)
	if err != nil {
		return Entry{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return Entry{}, err
	}
	defer resp.Body.Close() //nolint:errcheck // read failure surfaces below
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return Entry{}, fmt.Errorf("check status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return Entry{}, err
	}
	return Entry{
		Scheme:    c.Scheme,
		Addr:      proxyURL.Host,
		Latency:   time.Since(start),
		ExitIP:    exitIPFromTrace(string(body)),
		CheckedAt: time.Now(),
	}, nil
}

// exitIPFromTrace reads the ip= line of a cdn-cgi/trace-style body; empty
// when the body carries none.
func exitIPFromTrace(body string) string {
	for line := range strings.SplitSeq(body, "\n") {
		if ip, ok := strings.CutPrefix(strings.TrimSpace(line), "ip="); ok {
			return strings.TrimSpace(ip)
		}
	}
	return ""
}

// Refresh scrapes the sources, checks every candidate concurrently and
// replaces the pool with the survivors sorted by latency. It returns the
// number of seen and kept candidates.
func (p *Pool) Refresh(ctx context.Context, sources []string, checkURL string,
	timeout time.Duration, max, workers int,
	log func(format string, args ...any)) (seen, kept int) {
	if !p.BeginScan() {
		return 0, 0
	}
	candidates := FetchSources(ctx, sources, timeout, log)
	results := make(chan Entry, len(candidates))
	sem := make(chan struct{}, maxWorkers(workers))
	var wg sync.WaitGroup
	for _, c := range candidates {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(c Candidate) {
			defer wg.Done()
			defer func() { <-sem }()
			e, err := Check(ctx, c, checkURL, timeout)
			if err != nil {
				return
			}
			results <- e
		}(c)
	}
	wg.Wait()
	close(results)
	var verified []Entry
	for e := range results {
		verified = append(verified, e)
	}
	sortByLatency(verified)
	if max > 0 && len(verified) > max {
		verified = verified[:max]
	}
	p.Set(verified)
	p.EndScan(len(verified), len(candidates))
	return len(candidates), len(verified)
}

// maxWorkers bounds the check concurrency.
func maxWorkers(w int) int {
	if w < 1 || w > 500 {
		return 100
	}
	return w
}

// sortByLatency orders fastest first.
func sortByLatency(entries []Entry) {
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Latency < entries[j].Latency
	})
}
