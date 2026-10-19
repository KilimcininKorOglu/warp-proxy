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
	defer resp.Body.Close()
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
	if line == "" || strings.HasPrefix(line, "#") {
		return Candidate{}, false
	}
	if strings.ContainsRune(line, ' ') || strings.ContainsRune(line, '\t') {
		return Candidate{}, false
	}
	c := Candidate{Scheme: "http"}
	if i := strings.Index(line, "://"); i >= 0 {
		c.Scheme = strings.ToLower(line[:i])
		line = line[i+3:]
	}
	if !supportedSchemes[c.Scheme] {
		return Candidate{}, false
	}
	if i := strings.Index(line, "@"); i >= 0 {
		cred := line[:i]
		line = line[i+1:]
		user, pass, ok := strings.Cut(cred, ":")
		if !ok {
			return Candidate{}, false
		}
		c.Username, c.Password = user, pass
	}
	host, portStr, err := net.SplitHostPort(line)
	if err != nil {
		return Candidate{}, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 || host == "" ||
		strings.ContainsAny(host, "/?") {
		return Candidate{}, false
	}
	c.Host, c.Port = host, port
	return c, true
}

// parseProxyURL builds the *url.URL the stdlib transport needs.
func parseProxyURL(raw string) (*url.URL, error) {
	return url.Parse(raw)
}
