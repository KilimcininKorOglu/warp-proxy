package bridge

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"warp-proxy/internal/config"
	"warp-proxy/internal/logbuf"
	"warp-proxy/internal/proxy"
)

func TestRetryAfterParsing(t *testing.T) {
	mk := func(v string) *http.Response {
		r := &http.Response{Header: http.Header{}}
		if v != "" {
			r.Header.Set("Retry-After", v)
		}
		return r
	}
	if d := retryAfter(mk("3"), time.Now()); d != 3*time.Second {
		t.Errorf("seconds parse = %v, want 3s", d)
	}
	if d := retryAfter(mk("9999"), time.Now()); d != maxRetryWait {
		t.Errorf("cap = %v, want %v", d, maxRetryWait)
	}
	if d := retryAfter(mk("-5"), time.Now()); d != 0 {
		t.Errorf("negative = %v, want 0", d)
	}
	if d := retryAfter(mk(time.Now().Add(2*time.Second).UTC().Format(http.TimeFormat)), time.Now()); d <= 0 || d > maxRetryWait {
		t.Errorf("date parse = %v", d)
	}
	if d := retryAfter(mk(""), time.Now()); d != 0 {
		t.Errorf("missing header = %v, want 0", d)
	}
	if d := retryAfter(mk("garbage"), time.Now()); d != 0 {
		t.Errorf("garbage = %v, want 0", d)
	}
}

func TestRetryable(t *testing.T) {
	cfg := config.BridgeConfig{RetryStatuses: []int{429}}
	if !retryable(cfg, 429) {
		t.Error("429 not retryable")
	}
	if retryable(cfg, 500) {
		t.Error("500 wrongly retryable")
	}
	if retryable(config.BridgeConfig{}, 429) {
		t.Error("empty config wrongly retryable")
	}
}

// startBridge wires a bridge Server to a scripted upstream through the SOCKS5
// fake (the warp-cli stand-in) and returns the client-facing bridge server.
// inject toggles free-tier session injection, retryAttempts bounds replays,
// rotateSessionOnRetry refreshes the injected ids after a WARP rotation.
func startBridge(t *testing.T, upstreamHandler http.HandlerFunc,
	rotate func(context.Context) error, inject bool, retryAttempts int,
	rotateSessionOnRetry bool) *httptest.Server {
	t.Helper()

	socksLn := fakeSocks(t)
	upstream := httptest.NewServer(upstreamHandler)
	t.Cleanup(upstream.Close)

	cfg := func() config.BridgeConfig {
		return config.BridgeConfig{
			Enabled:              true,
			Upstream:             upstream.URL,
			RetryStatuses:        []int{429},
			RetryAttempts:        retryAttempts,
			MaxConcurrent:        3,
			MinInterval:          "0s",
			Timeout:              "10s",
			InjectSession:        inject,
			RotateSessionOnRetry: rotateSessionOnRetry,
		}
	}
	srv := New(&proxy.Upstream{Addr: socksLn, Timeout: 5 * time.Second},
		logbuf.New(32), discardLogger(), rotate, cfg)

	bridge := httptest.NewServer(srv)
	t.Cleanup(bridge.Close)
	return bridge
}

// fixture wires a bridge Server to a scripted upstream through the SOCKS5
// fake, reimplemented here for isolation.
func fixture(t *testing.T, upstreamHandler http.HandlerFunc, rotations *atomic.Int32) *httptest.Server {
	t.Helper()
	rotate := func(context.Context) error {
		rotations.Add(1)
		return nil
	}
	return startBridge(t, upstreamHandler, rotate, false, 1, false)
}

func TestForwardsAndPreservesHeaders(t *testing.T) {
	var gotPath, gotAuth, gotCT string
	bridge := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotCT = r.Header.Get("Content-Type")
		io.WriteString(w, `{"ok":true}`)
	}, &atomic.Int32{})

	req, _ := http.NewRequest("POST", bridge.URL+"/v1/chat/completions",
		bytes.NewBufferString(`{"model":"x"}`))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != `{"ok":true}` {
		t.Errorf("status=%d body=%q", resp.StatusCode, body)
	}
	if gotPath != "/v1/chat/completions" {
		t.Errorf("path = %q", gotPath)
	}
	if gotAuth != "Bearer test-key" || gotCT != "application/json" {
		t.Errorf("headers lost: auth=%q ct=%q", gotAuth, gotCT)
	}
}

func TestReplaysWithRotationOn429(t *testing.T) {
	var calls atomic.Int32
	var sawFirstBody, sawReplayBody atomic.Bool
	rotations := &atomic.Int32{}

	bridge := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if calls.Add(1) == 1 {
			sawFirstBody.Store(string(body) == `{"prompt":"hi"}`)
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(429)
			io.WriteString(w, `{"error":"FreeUsageLimitError"}`)
			return
		}
		sawReplayBody.Store(string(body) == `{"prompt":"hi"}`)
		io.WriteString(w, `{"ok":true}`)
	}, rotations)

	resp, err := http.Post(bridge.URL+"/v1/chat/completions", "application/json",
		bytes.NewBufferString(`{"prompt":"hi"}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 || string(respBody) != `{"ok":true}` {
		t.Errorf("final status=%d body=%q", resp.StatusCode, respBody)
	}
	if calls.Load() != 2 {
		t.Errorf("upstream calls = %d, want 2", calls.Load())
	}
	if rotations.Load() != 1 {
		t.Errorf("rotations = %d, want 1", rotations.Load())
	}
	if !sawFirstBody.Load() || !sawReplayBody.Load() {
		t.Error("replayed request body was not preserved byte-for-byte")
	}
}

func TestNonRetryableStatusPassesThrough(t *testing.T) {
	var calls atomic.Int32
	rotations := &atomic.Int32{}
	bridge := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) > 1 {
			t.Error("unexpected replay")
		}
		w.WriteHeader(403)
		io.WriteString(w, `denied`)
	}, rotations)

	resp, err := http.Get(bridge.URL + "/v1/models")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	if rotations.Load() != 0 {
		t.Errorf("rotations = %d, want 0", rotations.Load())
	}
}

func TestGivesUpAfterAttempts(t *testing.T) {
	var calls atomic.Int32
	rotations := &atomic.Int32{}
	bridge := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(429)
	}, rotations)

	resp, err := http.Get(bridge.URL + "/v1/models")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 429 {
		t.Errorf("status = %d, want 429", resp.StatusCode)
	}
	// Initial attempt plus one configured replay.
	if calls.Load() != 2 {
		t.Errorf("upstream calls = %d, want 2", calls.Load())
	}
	if rotations.Load() != 1 {
		t.Errorf("rotations = %d, want 1", rotations.Load())
	}
}

func TestOversizedBodyRejected(t *testing.T) {
	bridge := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("oversized body reached upstream")
	}, &atomic.Int32{})

	big := strings.Repeat("x", maxBody+10)
	resp, err := http.Post(bridge.URL+"/v1/x", "text/plain", bytes.NewBufferString(big))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", resp.StatusCode)
	}
}
