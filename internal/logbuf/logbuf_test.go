package logbuf

import (
	"fmt"
	"testing"
)

func TestNewestFirstAndOverwrite(t *testing.T) {
	b := New(3)
	for i := range 5 {
		b.Add("info", "request", "entry %d", i)
	}
	got := b.Snapshot(0)
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	// Newest first: entries 4, 3, 2 survive in a ring of 3.
	if got[0].Text != "entry 4" || got[2].Text != "entry 2" {
		t.Errorf("order wrong: %q, %q, %q", got[0].Text, got[1].Text, got[2].Text)
	}
}

func TestSnapshotLimit(t *testing.T) {
	b := New(10)
	for i := range 7 {
		b.Add("info", "request", "e%d", i)
	}
	got := b.Snapshot(2)
	if len(got) != 2 || got[0].Text != "e6" {
		t.Errorf("limit snapshot wrong: %v", got)
	}
}

func TestClear(t *testing.T) {
	b := New(4)
	b.Add("info", "warp", "x")
	b.Clear()
	if got := b.Snapshot(0); len(got) != 0 {
		t.Errorf("clear left %d entries", len(got))
	}
	// The buffer must stay usable after Clear.
	b.Add("info", "warp", "after")
	if got := b.Snapshot(0); len(got) != 1 || got[0].Text != "after" {
		t.Errorf("post-clear add broken: %v", got)
	}
}

func TestFormatArgs(t *testing.T) {
	b := New(2)
	b.Add("warn", "retry", "%s:%d", "host", 42)
	got := b.Snapshot(0)
	want := fmt.Sprintf("%s:%d", "host", 42)
	if got[0].Text != want {
		t.Errorf("text = %q, want %q", got[0].Text, want)
	}
}
