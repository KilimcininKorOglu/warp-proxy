// Package logbuf keeps a bounded ring of recent log entries for the web panel.
package logbuf

import (
	"fmt"
	"sync"
	"time"
)

// Entry is one log record shown in the panel.
type Entry struct {
	Time  time.Time `json:"time"`
	Level string    `json:"level"`
	Kind  string    `json:"kind"` // request | retry | reconnect | health | warp
	Text  string    `json:"text"`
}

// Buffer is a fixed-size ring buffer of entries. It is safe for concurrent
// use.
type Buffer struct {
	mu      sync.Mutex
	entries []Entry
	head    int // next write position
	count   int
}

// New returns a Buffer holding up to size entries.
func New(size int) *Buffer {
	if size < 1 {
		size = 1
	}
	return &Buffer{entries: make([]Entry, size)}
}

// Add appends one entry, overwriting the oldest when full.
func (b *Buffer) Add(level, kind, format string, args ...any) {
	msg := format
	if len(args) > 0 {
		msg = fmt.Sprintf(format, args...)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries[b.head] = Entry{
		Time:  time.Now(),
		Level: level,
		Kind:  kind,
		Text:  msg,
	}
	b.head = (b.head + 1) % len(b.entries)
	if b.count < len(b.entries) {
		b.count++
	}
}

// Snapshot returns the newest entries first, up to limit (0 means all).
func (b *Buffer) Snapshot(limit int) []Entry {
	b.mu.Lock()
	defer b.mu.Unlock()

	out := make([]Entry, 0, b.count)
	for i := 0; i < b.count; i++ {
		idx := (b.head - 1 - i + 2*len(b.entries)) % len(b.entries)
		out = append(out, b.entries[idx])
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Clear drops every entry.
func (b *Buffer) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries = make([]Entry, len(b.entries))
	b.head = 0
	b.count = 0
}
