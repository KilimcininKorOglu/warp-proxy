// Package cleanip measures latency from this host to candidate Cloudflare
// edge IPs and ranks the fastest reachable ones. Measurements run on the
// server directly (not through WARP), because the goal is to pick the edge
// the WARP tunnel itself will use.
package cleanip

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RangesURL is Cloudflare's official IPv4 range list.
const RangesURL = "https://www.cloudflare.com/ips-v4"

// Params controls one scan.
type Params struct {
	// Port is the TCP port probed on every candidate (443 default).
	Port int
	// SamplesPerRange is how many candidate IPs each CIDR contributes.
	SamplesPerRange int
	// Workers bounds concurrent probes.
	Workers int
	// Timeout bounds one TCP connect.
	Timeout time.Duration
	// Top truncates the sorted result list; 0 keeps everything.
	Top int
}

// Result is one measured candidate.
type Result struct {
	IP      string        `json:"ip"`
	Latency time.Duration `json:"latency"`
}

// FetchRanges downloads the official Cloudflare IPv4 CIDR list.
func FetchRanges(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, RangesURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch ranges: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch ranges: status %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("read ranges: %w", err)
	}
	var ranges []string
	for line := range strings.SplitSeq(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			ranges = append(ranges, line)
		}
	}
	if len(ranges) == 0 {
		return nil, fmt.Errorf("no ranges in response from %s", RangesURL)
	}
	return ranges, nil
}

// Candidates picks n evenly spaced IPs from each CIDR.
func Candidates(ranges []string, n int) ([]string, error) {
	if n < 1 {
		n = 1
	}
	var out []string
	for _, cidr := range ranges {
		base, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("parse range %q: %w", cidr, err)
		}
		start := binary.BigEndian.Uint32(base.To4())
		end := broadcast(start, ipnet)
		size := end - start + 1
		if size == 0 {
			continue
		}
		step := size / uint32(n)
		if step == 0 {
			step = 1
		}
		for i := uint32(0); i < uint32(n); i++ {
			// Small ranges repeat their single addresses rather than
			// spilling past the broadcast address.
			offset := min(i*step, size-1)
			ip := make(net.IP, 4)
			binary.BigEndian.PutUint32(ip, start+offset)
			out = append(out, ip.String())
		}
	}
	return out, nil
}

// broadcast returns the last address of the network containing start.
func broadcast(start uint32, ipnet *net.IPNet) uint32 {
	mask := binary.BigEndian.Uint32(ipnet.Mask)
	return start | ^mask
}

// Probe measures one TCP connect to ip:port.
func Probe(ctx context.Context, ip string, port int, timeout time.Duration) (time.Duration, error) {
	d := net.Dialer{Timeout: timeout}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return 0, err
	}
	latency := time.Since(start)
	conn.Close()
	return latency, nil
}

// Scan probes every candidate concurrently and returns the reachable ones
// sorted by latency, ascending, truncated to top.
func Scan(ctx context.Context, params Params, ranges []string) []Result {
	candidates, err := Candidates(ranges, params.SamplesPerRange)
	if err != nil {
		return nil
	}
	if params.Workers < 1 {
		params.Workers = 1
	}

	results := make(chan Result, len(candidates))
	jobs := make(chan string)
	var wg sync.WaitGroup
	for range params.Workers {
		wg.Go(func() {
			for ip := range jobs {
				if latency, err := Probe(ctx, ip, params.Port, params.Timeout); err == nil {
					results <- Result{IP: ip, Latency: latency}
				}
			}
		})
	}
	for _, ip := range candidates {
		jobs <- ip
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	var reachable []Result
	for r := range results {
		reachable = append(reachable, r)
	}
	sort.Slice(reachable, func(i, j int) bool {
		return reachable[i].Latency < reachable[j].Latency
	})
	if params.Top > 0 && len(reachable) > params.Top {
		reachable = reachable[:params.Top]
	}
	return reachable
}

// ScanHostPorts probes the CONNECT-IP service ports of one host (the
// registration's home edge) and ranks the reachable ones. The returned
// Result.IP is "host:port", ready to use as a pinned endpoint: MASQUE binds
// a registration to its home edge, so scans must not wander to other
// Cloudflare addresses.
func ScanHostPorts(ctx context.Context, host string, ports []int,
	timeout time.Duration, top int) []Result {
	results := make(chan Result, len(ports))
	var wg sync.WaitGroup
	for _, port := range ports {
		wg.Go(func() {
			if latency, err := Probe(ctx, host, port, timeout); err == nil {
				results <- Result{IP: net.JoinHostPort(host, strconv.Itoa(port)),
					Latency: latency}
			}
		})
	}
	go func() {
		wg.Wait()
		close(results)
	}()
	var reachable []Result
	for r := range results {
		reachable = append(reachable, r)
	}
	sort.Slice(reachable, func(i, j int) bool {
		return reachable[i].Latency < reachable[j].Latency
	})
	if top > 0 && len(reachable) > top {
		reachable = reachable[:top]
	}
	return reachable
}
