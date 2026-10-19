package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"warp-proxy/internal/config"
	"warp-proxy/internal/logbuf"
)

func TestRetryAfterParsing(t *testing.T) {
	mk := func(v string) *http.Response {
		r := &http.Response{Header: http.Header{}}
		if v != "" {
			r.Header.Set("Retry-After", v)
		}
		return r
	}
	if d, ok := retryAfter(mk("3"), time.Now()); !ok || d != 3*time.Second {
		t.Errorf("seconds parse = %v ok=%v, want 3s", d, ok)
	}
	if d, ok := retryAfter(mk("9999"), time.Now()); !ok || d != maxRetryWait {
		t.Errorf("cap = %v ok=%v, want %v", d, ok, maxRetryWait)
	}
	if d, ok := retryAfter(mk("-5"), time.Now()); !ok || d != 0 {
		t.Errorf("negative = %v ok=%v, want 0", d, ok)
	}
	if d, ok := retryAfter(mk(time.Now().Add(2*time.Second).UTC().Format(http.TimeFormat)), time.Now()); !ok || d <= 0 || d > maxRetryWait {
		t.Errorf("date parse = %v ok=%v", d, ok)
	}
	if _, ok := retryAfter(mk(""), time.Now()); ok {
		t.Error("missing header reported parsable")
	}
	if _, ok := retryAfter(mk("garbage"), time.Now()); ok {
		t.Error("garbage header reported parsable")
	}
}

func TestRetryWait(t *testing.T) {
	mk := func(v string) *http.Response {
		r := &http.Response{Header: http.Header{}}
		if v != "" {
			r.Header.Set("Retry-After", v)
		}
		return r
	}
	if d := retryWait(mk("0"), time.Now()); d != 0 {
		t.Errorf("explicit zero = %v, want 0 (no default)", d)
	}
	if d := retryWait(mk("3"), time.Now()); d != 3*time.Second {
		t.Errorf("hint = %v, want 3s", d)
	}
	if d := retryWait(mk(""), time.Now()); d != defaultRetryWait {
		t.Errorf("missing hint = %v, want %v", d, defaultRetryWait)
	}
	if d := retryWait(mk("garbage"), time.Now()); d != defaultRetryWait {
		t.Errorf("garbage hint = %v, want %v", d, defaultRetryWait)
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

// startBridge wires a bridge Server to a scripted upstream through the
// direct-dial fake (the tunnel stand-in) and returns the client-facing
// bridge server.
// inject toggles free-tier session injection, retryAttempts bounds replays,
// rotateSessionOnRetry refreshes the injected ids after a WARP rotation.
func startBridge(t *testing.T, upstreamHandler http.HandlerFunc,
	rotate func(context.Context) error, inject bool, retryAttempts int,
	rotateSessionOnRetry bool) *httptest.Server {
	t.Helper()

	upstream := httptest.NewServer(upstreamHandler)
	t.Cleanup(upstream.Close)
	tURL, _ := url.Parse(upstream.URL)

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
	srv := New(dialUpstream(tURL.Host), logbuf.New(32), discardLogger(), rotate, cfg)

	bridge := httptest.NewServer(srv)
	t.Cleanup(bridge.Close)
	return bridge
}

// fixture wires a bridge Server to a scripted upstream, reimplemented here
// for isolation.
func fixture(t *testing.T, upstreamHandler http.HandlerFunc, rotations *atomic.Int32) *httptest.Server {
	t.Helper()
	rotate := func(context.Context) error {
		rotations.Add(1)
		return nil
	}
	return startBridge(t, upstreamHandler, rotate, false, 1, false)
}

// TestHealthNotProxied verifies the local /health path answers without
// reaching the upstream, so probes spend no quota.
func TestHealthNotProxied(t *testing.T) {
	var upstreamHits atomic.Int32
	bridge := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		io.WriteString(w, `{"ok":true}`)
	}, &atomic.Int32{})

	resp, err := http.Get(bridge.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok\n" {
		t.Errorf("body = %q, want %q", body, "ok\n")
	}
	if n := upstreamHits.Load(); n != 0 {
		t.Errorf("upstream hit %d times, want 0", n)
	}

	// A path that merely contains the prefix must still be proxied.
	resp2, err := http.Get(bridge.URL + "/health/check")
	if err != nil {
		t.Fatalf("GET /health/check: %v", err)
	}
	defer resp2.Body.Close()
	if n := upstreamHits.Load(); n != 1 {
		t.Errorf("upstream hits = %d, want 1 for /health/check", n)
	}
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

func TestReplaysWithRotationOnUsageLimit(t *testing.T) {
	var calls atomic.Int32
	var sawFirstBody, sawReplayBody atomic.Bool
	rotations := &atomic.Int32{}

	bridge := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if calls.Add(1) == 1 {
			sawFirstBody.Store(string(body) == `{"prompt":"hi"}`)
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(429)
			io.WriteString(w, `{"error":{"type":"FreeUsageLimitError"}}`)
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
		// A plain 429 is retried on the same IP, so it must not rotate.
		w.Header().Set("Retry-After", "0")
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
	if rotations.Load() != 0 {
		t.Errorf("rotations = %d, want 0 (a plain 429 does not rotate)", rotations.Load())
	}
}

func TestPlain429RetriesWithoutRotation(t *testing.T) {
	var calls atomic.Int32
	rotations := &atomic.Int32{}
	bridge := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(429)
			io.WriteString(w, `{"error":{"type":"RateLimitError"}}`)
			return
		}
		io.WriteString(w, `{"ok":true}`)
	}, rotations)

	resp, err := http.Get(bridge.URL + "/v1/models")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(respBody) != `{"ok":true}` {
		t.Errorf("status=%d body=%q, want 200/ok", resp.StatusCode, respBody)
	}
	if calls.Load() != 2 || rotations.Load() != 0 {
		t.Errorf("calls=%d rotations=%d, want 2/0", calls.Load(), rotations.Load())
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

// TestJSONCallerGetsAggregatedStream proves gate-4 handling: the client
// asks for JSON, the bridge forces stream:true upstream, the scripted
// upstream answers with SSE, and the caller still receives one
// chat.completion object carrying the full content.
func TestJSONCallerGetsAggregatedStream(t *testing.T) {
	bridge := startBridge(t, func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Stream *bool `json:"stream"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Stream == nil || !*body.Stream {
			t.Error("upstream did not receive stream:true")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {\"id\":\"c1\",\"model\":\"m\",\"choices\":[{\"index\":0,"+
			"\"delta\":{\"content\":\"hi there\"},\"finish_reason\":\"stop\"}]}\n\n")
		io.WriteString(w, "data: [DONE]\n\n")
	}, func(context.Context) error { return nil }, true, 0, false)

	resp, err := http.Post(bridge.URL+"/v1/chat/completions", "application/json",
		bytes.NewBufferString(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, out)
	}
	var completion struct {
		Object  string `json:"object"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(out, &completion); err != nil {
		t.Fatalf("body is not a chat.completion: %s", out)
	}
	if completion.Object != "chat.completion" || len(completion.Choices) == 0 ||
		completion.Choices[0].Message.Content != "hi there" {
		t.Errorf("aggregated completion = %s", out)
	}
}

// TestAnthropicMessagesEndToEnd proves /v1/messages: the Anthropic-shaped
// request is translated, answered from the upstream SSE stream, and
// returned in the Anthropic envelope.
func TestAnthropicMessagesEndToEnd(t *testing.T) {
	var gotPath, gotUA string
	bridge := startBridge(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotUA = r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {\"id\":\"c9\",\"model\":\"big-pickle\",\"choices\":["+""+
			"{\"index\":0,\"delta\":{\"content\":\"translated\"},\"finish_reason\":\"stop\"}]}\n\n")
	}, func(context.Context) error { return nil }, true, 0, false)

	anthropicBody := `{"model":"big-pickle","max_tokens":100,
		"system":"be brief",
		"messages":[{"role":"user","content":[{"type":"text","text":"selam"}]}]}`
	resp, err := http.Post(bridge.URL+"/v1/messages", "application/json",
		bytes.NewBufferString(anthropicBody))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, out)
	}
	if gotPath != "/v1/chat/completions" {
		t.Errorf("upstream path = %q, want the chat completions path", gotPath)
	}
	if !strings.HasPrefix(gotUA, "opencode/") {
		t.Errorf("UA = %q, want an opencode UA", gotUA)
	}
	var msg struct {
		Type    string `json:"type"`
		Role    string `json:"role"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(out, &msg); err != nil {
		t.Fatalf("body is not an anthropic message: %s", out)
	}
	if msg.Type != "message" || msg.Role != "assistant" || len(msg.Content) == 0 ||
		msg.Content[0].Text != "translated" {
		t.Errorf("anthropic message = %s", out)
	}
}

// TestPublicProxyFallbackAfterExhaustedRetries proves the public pool is
// the last resort: the upstream keeps answering the free-tier 429, the WARP
// retries run out, and the final attempt exits through the public proxy.
func TestPublicProxyFallbackAfterExhaustedRetries(t *testing.T) {
	var upstreamCalls, publicCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"error":{"type":"FreeUsageLimitError"}}`)
	}))
	t.Cleanup(upstream.Close)
	public := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		publicCalls.Add(1)
		_, _ = io.WriteString(w, `{"via":"public"}`)
	}))
	t.Cleanup(public.Close)
	tURL, _ := url.Parse(upstream.URL)

	srv := New(dialUpstream(tURL.Host), logbuf.New(32), discardLogger(),
		func(context.Context) error { return nil },
		func() config.BridgeConfig {
			return config.BridgeConfig{
				Enabled:       true,
				Upstream:      upstream.URL,
				RetryStatuses: []int{429},
				RetryAttempts: 1,
				MaxConcurrent: 3,
				MinInterval:   "0s",
				Timeout:       "10s",
			}
		})
	pu, _ := url.Parse(public.URL)
	srv.Public = func(context.Context) *http.Transport {
		return &http.Transport{Proxy: http.ProxyURL(pu)}
	}
	bridgeSrv := httptest.NewServer(srv)
	t.Cleanup(bridgeSrv.Close)

	resp, err := http.Post(bridgeSrv.URL+"/v1/chat/completions", "application/json",
		bytes.NewBufferString(`{"prompt":"hi"}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 || string(body) != `{"via":"public"}` {
		t.Errorf("status=%d body=%q, want 200 via public", resp.StatusCode, body)
	}
	if upstreamCalls.Load() != 2 {
		t.Errorf("upstream calls = %d, want 2 (initial + one replay)", upstreamCalls.Load())
	}
	if publicCalls.Load() != 1 {
		t.Errorf("public calls = %d, want 1 (fallback only after retries)", publicCalls.Load())
	}
}
