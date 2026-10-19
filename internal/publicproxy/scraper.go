package publicproxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Candidate is one scraped proxy candidate before verification.
type Candidate struct {
	Scheme   string
	Host     string
	Port     int
	Username string
	Password string
}

// Key identifies the candidate for deduplication.
func (c Candidate) Key() string {
	return c.Scheme + "://" + net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
}

// supportedSchemes maps list schemes to what the stdlib transport accepts;
// socks4 has no stdlib client and is dropped at check time.
var supportedSchemes = map[string]bool{
	"http": true, "https": true, "socks5": true, "socks5h": true,
}

// FetchSources downloads every source, parses the proxy lines and returns
// the deduplicated candidates. A failing source is skipped after logging.
func FetchSources(ctx context.Context, sources []string, timeout time.Duration,
	log func(format string, args ...any)) []Candidate {
	seen := map[string]bool{}
	var out []Candidate
	client := &http.Client{Timeout: timeout}
	for _, src := range sources {
		body, err := fetchOne(ctx, client, src)
		if err != nil {
			if log != nil {
				log("source %s: %v", src, err)
			}
			continue
		}
		n := 0
		for line := range strings.SplitSeq(body, "\n") {
			c, ok := parseProxyLine(line)
			if !ok || seen[c.Key()] {
				continue
			}
			seen[c.Key()] = true
			out = append(out, c)
			n++
		}
		if log != nil {
			log("source %s: %d candidates", src, n)
		}
	}
	return out
}

// fetchOne downloads one source as text.
func fetchOne(ctx context.Context, client *http.Client, src string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint:errcheck // read failure surfaces below
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// parseProxyLine reads one list line: "scheme://[user:pass@]host:port",
// with the scheme defaulting to http on bare "host:port" lines. Comments
// and blanks return false.
func parseProxyLine(line string) (Candidate, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") ||
		strings.ContainsAny(line, " \t") {
		return Candidate{}, false
	}
	scheme, rest := splitScheme(line)
	if !supportedSchemes[scheme] {
		return Candidate{}, false
	}
	user, pass, rest, ok := splitUserPass(rest)
	if !ok {
		return Candidate{}, false
	}
	host, port, ok := splitHostPort(rest)
	if !ok {
		return Candidate{}, false
	}
	return Candidate{Scheme: scheme, Host: host, Port: port, Username: user,
		Password: pass}, true
}

// splitScheme splits an optional leading "scheme://" and lowercases it,
// defaulting to http. rest is everything after "://".
func splitScheme(line string) (scheme, rest string) {
	if before, after, ok := strings.Cut(line, "://"); ok {
		return strings.ToLower(before), after
	}
	return "http", line
}

// splitUserPass splits an optional "user:pass@" prefix.
func splitUserPass(rest string) (user, pass, addr string, ok bool) {
	before, after, ok := strings.Cut(rest, "@")
	if !ok {
		return "", "", rest, true
	}
	user, pass, found := strings.Cut(before, ":")
	if !found {
		return "", "", "", false
	}
	return user, pass, after, true
}

// splitHostPort validates and splits "host:port" into its parts.
func splitHostPort(addr string) (host string, port int, ok bool) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, false
	}
	port, err = strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 || host == "" ||
		strings.ContainsAny(host, "/?") {
		return "", 0, false
	}
	return host, port, true
}

// parseProxyURL builds the *url.URL the stdlib transport needs.
func parseProxyURL(raw string) (*url.URL, error) {
	return url.Parse(raw)
}
