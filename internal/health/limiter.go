// Package health checks the WARP exit against configured bot markers and
// rate-limits reconnects.
package health

import (
	"fmt"
	"sync"
	"time"
)

// Limiter is the reconnect rate limiter: no reconnect more often than
// MinInterval, at most MaxConsecutive in a row, then Cooldown silence.
type Limiter struct {
	MinInterval    time.Duration
	MaxConsecutive int
	Cooldown       time.Duration

	mu              sync.Mutex
	lastAttempt     time.Time
	consecutive     int
	cooldownUntil   time.Time
	totalReconnects int64
}

// Decision explains the outcome of a reconnect request.
type Decision struct {
	Allowed  bool
	Reason   string
	WaitLeft time.Duration
}

// Allow reports whether a reconnect may run now.
func (l *Limiter) Allow(now time.Time) Decision {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.cooldownUntil.IsZero() && now.Before(l.cooldownUntil) {
		return Decision{
			Allowed:  false,
			Reason:   "cooldown after reconnect burst",
			WaitLeft: l.cooldownUntil.Sub(now),
		}
	}
	if !l.lastAttempt.IsZero() {
		elapsed := now.Sub(l.lastAttempt)
		if elapsed < l.MinInterval {
			return Decision{
				Allowed:  false,
				Reason:   "min reconnect interval not elapsed",
				WaitLeft: l.MinInterval - elapsed,
			}
		}
	}
	return Decision{Allowed: true}
}

// Record counts a reconnect attempt, including its result.
func (l *Limiter) Record(now time.Time, succeeded bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.lastAttempt = now
	l.totalReconnects++
	if succeeded {
		l.consecutive = 0
		l.cooldownUntil = time.Time{}
		return
	}
	l.consecutive++
	if l.MaxConsecutive > 0 && l.consecutive >= l.MaxConsecutive {
		l.cooldownUntil = now.Add(l.Cooldown)
	}
}

// Snapshot returns the limiter state for the panel.
type LimiterState struct {
	Consecutive     int       `json:"consecutive"`
	TotalReconnects int64     `json:"total_reconnects"`
	CooldownUntil   time.Time `json:"cooldown_until"`
	LastAttempt     time.Time `json:"last_attempt"`
}

func (l *Limiter) snapshot() LimiterState {
	l.mu.Lock()
	defer l.mu.Unlock()
	return LimiterState{
		Consecutive:     l.consecutive,
		TotalReconnects: l.totalReconnects,
		CooldownUntil:   l.cooldownUntil,
		LastAttempt:     l.lastAttempt,
	}
}

// String renders a decision for logs.
func (d Decision) String() string {
	if d.Allowed {
		return "allowed"
	}
	return fmt.Sprintf("denied (%s), retry in %s", d.Reason, d.WaitLeft.Truncate(time.Second))
}
