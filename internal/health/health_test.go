package health

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"warp-proxy/internal/logbuf"
	"warp-proxy/internal/proxy"
	"warp-proxy/internal/warp"
)

func TestLimiterMinInterval(t *testing.T) {
	l := &Limiter{MinInterval: time.Minute, MaxConsecutive: 3, Cooldown: 10 * time.Minute}
	now := time.Now()

	if !l.Allow(now).Allowed {
		t.Error("first reconnect denied")
	}
	l.Record(now, false)

	dec := l.Allow(now.Add(30 * time.Second))
	if dec.Allowed {
		t.Error("reconnect allowed inside min interval")
	}
	if dec.WaitLeft != 30*time.Second {
		t.Errorf("wait = %v, want 30s", dec.WaitLeft)
	}
	if !l.Allow(now.Add(time.Minute)).Allowed {
		t.Error("reconnect denied after min interval")
	}
}

func TestLimiterCooldownAfterBurst(t *testing.T) {
	l := &Limiter{MinInterval: time.Second, MaxConsecutive: 3, Cooldown: 10 * time.Minute}
	now := time.Now()

	for i := range 3 {
		l.Record(now.Add(time.Duration(i)*2*time.Second), false)
	}
	dec := l.Allow(now.Add(10 * time.Second))
	if dec.Allowed {
		t.Error("reconnect allowed during cooldown")
	}
	if !strings.Contains(dec.Reason, "cooldown") {
		t.Errorf("reason = %q, want cooldown", dec.Reason)
	}
	// A successful reconnect resets the burst counter and the cooldown.
	l.Record(now.Add(11*time.Minute), true)
	if !l.Allow(now.Add(11*time.Minute + l.MinInterval)).Allowed {
		t.Error("reconnect denied after successful reconnect")
	}
	if st := l.snapshot(); st.Consecutive != 0 {
		t.Errorf("consecutive = %d, want 0 after success", st.Consecutive)
	}
}

func TestParseTrace(t *testing.T) {
	body := []byte("fl=x\nip=203.0.113.7\nuuid=x\nwarp=on\nloc=DE\n")
	ip, on := parseTrace(body)
	if ip != "203.0.113.7" || !on {
		t.Errorf("ip=%q warpOn=%v, want 203.0.113.7 true", ip, on)
	}
	ip, on = parseTrace([]byte("warp=off\nip=198.51.100.1\n"))
	if ip != "198.51.100.1" || on {
		t.Errorf("ip=%q warpOn=%v, want 198.51.100.1 false", ip, on)
	}
}

// checkerFixture wires a Checker to a scripted health target and a mock
// warp-cli binary.
type checkerFixture struct {
	checker *Checker
	health  *httptest.Server
	reconns *int
}

func newFixture(t *testing.T, healthBody string) *checkerFixture {
	t.Helper()

	reconns := 0
	dir := t.TempDir()
	script := dir + "/warp-cli"
	body := "#!/bin/sh\n" +
		"echo \"$@\" >> " + dir + "/calls\n" +
		"if [ \"$1\" = \"disconnect\" ] || [ \"$1\" = \"connect\" ]; then echo reconns >> " + dir + "/calls; fi\n" +
		"exit 0\n"
	if err := writeFile(script, body); err != nil {
		t.Fatalf("write mock: %v", err)
	}

	health := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/trace") {
			_, _ = w.Write([]byte("ip=203.0.113.7\nwarp=on\n"))
			return
		}
		_, _ = w.Write([]byte(healthBody))
	}))
	t.Cleanup(health.Close)

	mgr := warp.NewManager(script, nil, warp.ModeReconnect)
	logs := logbuf.New(64)
	cfg := func() Config {
		return Config{
			Enabled:    true,
			URL:        health.URL + "/check",
			TraceURL:   health.URL + "/trace",
			Timeout:    5 * time.Second,
			BotMarkers: []string{"Sign in to confirm you're not a bot"},
		}
	}
	c := NewChecker(&proxy.Upstream{Addr: fakeUpstream(t)}, mgr, logs, discardLogger(), cfg)
	return &checkerFixture{checker: c, health: health, reconns: &reconns}
}

func TestRunOnceHealthyNoReconnect(t *testing.T) {
	f := newFixture(t, "all good")
	f.checker.RunOnce(context.Background())

	st := f.checker.Status()
	if !st.Healthy || st.ExitIP != "203.0.113.7" || !st.WarpOn {
		t.Errorf("status = %+v", st)
	}
	if !st.LastReconnect.IsZero() {
		t.Error("healthy run triggered a reconnect")
	}
}

func TestRunOnceFlaggedTriggersReconnect(t *testing.T) {
	f := newFixture(t, "Sign in to confirm you're not a bot")
	f.checker.UpdateLimiter(0, 3, time.Minute)

	f.checker.RunOnce(context.Background())
	st := f.checker.Status()
	if st.Healthy {
		t.Error("flagged run reported healthy")
	}
	if st.LastReconnect.IsZero() {
		t.Error("flagged run did not reconnect")
	}
	if st.Limiter.TotalReconnects != 1 {
		t.Errorf("total reconnects = %d, want 1", st.Limiter.TotalReconnects)
	}
}

func TestDisabledCheckerDoesNothing(t *testing.T) {
	f := newFixture(t, "Sign in to confirm you're not a bot")
	f.checker.cfg = func() Config { return Config{Enabled: false} }

	f.checker.RunOnce(context.Background())
	st := f.checker.Status()
	if st.LastRun.IsZero() {
		// RunOnce returns before touching state when disabled.
		return
	}
	t.Error("disabled check ran")
}
