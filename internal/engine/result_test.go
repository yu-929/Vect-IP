package engine

import (
	"math"
	"net/netip"
	"testing"
)

func addr(s string) netip.Addr {
	return netip.MustParseAddr(s)
}

func TestNewTopNCollector(t *testing.T) {
	c := NewTopNCollector(5, false)
	if c.n != 5 {
		t.Fatalf("expected n=5, got %d", c.n)
	}
	if c.Len() != 0 {
		t.Fatalf("expected empty, got %d", c.Len())
	}
}

func TestTopNColoDiversity(t *testing.T) {
	c := NewTopNCollector(4, true)
	// All from colo A: should all be accepted (heap not full)
	c.Consider(TopResult{IP: addr("1.1.1.1"), ScoreMS: 100, Trace: map[string]string{"colo": "A"}})
	c.Consider(TopResult{IP: addr("1.1.1.2"), ScoreMS: 90, Trace: map[string]string{"colo": "A"}})
	c.Consider(TopResult{IP: addr("1.1.1.3"), ScoreMS: 80, Trace: map[string]string{"colo": "A"}})
	c.Consider(TopResult{IP: addr("1.1.1.4"), ScoreMS: 70, Trace: map[string]string{"colo": "A"}})
	if c.Len() != 4 {
		t.Fatalf("expected 4 results, got %d", c.Len())
	}

	// New colo B with a better score: should replace global worst (col A 100ms)
	c.Consider(TopResult{IP: addr("2.2.2.1"), ScoreMS: 50, Trace: map[string]string{"colo": "B"}})
	if c.Len() != 4 {
		t.Fatalf("expected 4 results after colo B, got %d", c.Len())
	}
	snap := c.Snapshot()
	hasColoB := false
	hasOldWorst := false
	for _, r := range snap {
		if r.IP == addr("2.2.2.1") {
			hasColoB = true
		}
		if r.IP == addr("1.1.1.1") {
			hasOldWorst = true
		}
	}
	if !hasColoB {
		t.Fatal("expected colo B IP to be in results")
	}
	if hasOldWorst {
		t.Fatal("expected colo A worst (1.1.1.1) to be evicted")
	}

	// Another colo B entry with worse score than existing colo A entries: should replace colo B's own worst
	c.Consider(TopResult{IP: addr("2.2.2.2"), ScoreMS: 95, Trace: map[string]string{"colo": "B"}})
	// 2.2.2.2 at 95ms is worse than all colo A entries (70-90ms) but better than colo B's only entry (50ms? no, 50 < 95)
	// Actually 95 > 50, so 2.2.2.2 is worse than 2.2.2.1 (50ms). It should replace the global worst (95 > 70,80,90,50?)
	// Global worst is 90ms (1.1.1.2). Since colo B already has an entry, we try to find colo B's worst = 50ms (2.2.2.1).
	// 95 > 50, so we don't replace. Then we check global worst: 95 > 90, so we don't replace globally either.
	// Result: 2.2.2.2 should NOT be in the heap.
	if c.Len() != 4 {
		t.Fatalf("expected 4 results, got %d", c.Len())
	}
	hasNew := false
	for _, r := range c.Snapshot() {
		if r.IP == addr("2.2.2.2") {
			hasNew = true
		}
	}
	if hasNew {
		t.Fatal("expected 2.2.2.2 (95ms) to be rejected since it's worse than both colo B's own worst and global worst")
	}

	// colo B third entry with score better than colo B's worst: should replace colo B's worst
	c.Consider(TopResult{IP: addr("2.2.2.3"), ScoreMS: 45, Trace: map[string]string{"colo": "B"}})
	// colo B has 2.2.2.1 (50ms). 45 < 50, so replace colo B's worst (2.2.2.1 at 50ms).
	if c.Len() != 4 {
		t.Fatalf("expected 4 results, got %d", c.Len())
	}
	found := false
	oldGone := true
	for _, r := range c.Snapshot() {
		if r.IP == addr("2.2.2.3") {
			found = true
		}
		if r.IP == addr("2.2.2.1") {
			oldGone = false
		}
	}
	if !found {
		t.Fatal("expected 2.2.2.3 (45ms) to be in results")
	}
	if !oldGone {
		t.Fatal("expected 2.2.2.1 (50ms) to be evicted")
	}

	// Entry without colo: uses global replacement logic
	c = NewTopNCollector(4, true)
	c.Consider(TopResult{IP: addr("1.1.1.1"), ScoreMS: 100, Trace: map[string]string{"colo": "A"}})
	c.Consider(TopResult{IP: addr("1.1.1.2"), ScoreMS: 90, Trace: map[string]string{"colo": "A"}})
	c.Consider(TopResult{IP: addr("1.1.1.3"), ScoreMS: 80, Trace: map[string]string{"colo": "A"}})
	c.Consider(TopResult{IP: addr("3.3.3.3"), ScoreMS: 50, Trace: nil}) // no colo
	if c.Len() != 4 {
		t.Fatalf("expected 4 results, got %d", c.Len())
	}
	// Entry with nil colo: should replace global worst
	// Global worst is 100ms (1.1.1.1). 50 < 100, so it should be in.
	foundNil := false
	for _, r := range c.Snapshot() {
		if r.IP == addr("3.3.3.3") {
			foundNil = true
		}
	}
	if !foundNil {
		t.Fatal("expected entry without colo to be accepted via global replacement")
	}
}

func TestTopNCollectorConsider(t *testing.T) {
	c := NewTopNCollector(3, false)
	c.Consider(TopResult{IP: addr("1.1.1.1"), ScoreMS: 30})
	c.Consider(TopResult{IP: addr("1.1.1.2"), ScoreMS: 10})
	c.Consider(TopResult{IP: addr("1.1.1.3"), ScoreMS: 20})

	if c.Len() != 3 {
		t.Fatalf("expected 3 results, got %d", c.Len())
	}

	best := c.Best()
	if best.IP != addr("1.1.1.2") || best.ScoreMS != 10 {
		t.Fatalf("expected best 1.1.1.2/10ms, got %s/%.1fms", best.IP, best.ScoreMS)
	}
}

func TestTopNCollectorEvictsWorst(t *testing.T) {
	c := NewTopNCollector(2, false)
	c.Consider(TopResult{IP: addr("1.1.1.1"), ScoreMS: 50})
	c.Consider(TopResult{IP: addr("1.1.1.2"), ScoreMS: 10})
	c.Consider(TopResult{IP: addr("1.1.1.3"), ScoreMS: 20})

	if c.Len() != 2 {
		t.Fatalf("expected 2 results, got %d", c.Len())
	}

	snap := c.Snapshot()
	if snap[0].IP != addr("1.1.1.2") || snap[0].ScoreMS != 10 {
		t.Fatalf("expected best 1.1.1.2/10ms, got %s/%.1fms", snap[0].IP, snap[0].ScoreMS)
	}
	if snap[1].IP != addr("1.1.1.3") || snap[1].ScoreMS != 20 {
		t.Fatalf("expected second 1.1.1.3/20ms, got %s/%.1fms", snap[1].IP, snap[1].ScoreMS)
	}
}

func TestTopNCollectorDedupUpdatesBetter(t *testing.T) {
	c := NewTopNCollector(3, false)
	c.Consider(TopResult{IP: addr("1.1.1.1"), ScoreMS: 100})
	c.Consider(TopResult{IP: addr("1.1.1.1"), ScoreMS: 30})

	if c.Len() != 1 {
		t.Fatalf("expected 1 result after dedup, got %d", c.Len())
	}
	best := c.Best()
	if best.ScoreMS != 30 {
		t.Fatalf("expected updated score 30, got %.1f", best.ScoreMS)
	}
}

func TestTopNCollectorDedupIgnoresWorse(t *testing.T) {
	c := NewTopNCollector(3, false)
	c.Consider(TopResult{IP: addr("1.1.1.1"), ScoreMS: 30})
	c.Consider(TopResult{IP: addr("1.1.1.1"), ScoreMS: 50})

	if c.Len() != 1 {
		t.Fatalf("expected 1 result, got %d", c.Len())
	}
	best := c.Best()
	if best.ScoreMS != 30 {
		t.Fatalf("expected original score 30, got %.1f", best.ScoreMS)
	}
}

func TestTopNCollectorSnapshotOrder(t *testing.T) {
	c := NewTopNCollector(5, false)
	c.Consider(TopResult{IP: addr("1.1.1.1"), ScoreMS: 50})
	c.Consider(TopResult{IP: addr("1.1.1.2"), ScoreMS: 10})
	c.Consider(TopResult{IP: addr("1.1.1.3"), ScoreMS: 30})
	c.Consider(TopResult{IP: addr("1.1.1.4"), ScoreMS: 20})
	c.Consider(TopResult{IP: addr("1.1.1.5"), ScoreMS: 40})

	snap := c.Snapshot()
	if len(snap) != 5 {
		t.Fatalf("expected 5 results, got %d", len(snap))
	}
	for i := 1; i < len(snap); i++ {
		if snap[i].ScoreMS < snap[i-1].ScoreMS {
			t.Fatalf("snapshot not sorted at index %d: %.1f < %.1f", i, snap[i].ScoreMS, snap[i-1].ScoreMS)
		}
	}
}

func TestTopNCollectorBestEmpty(t *testing.T) {
	c := NewTopNCollector(3, false)
	best := c.Best()
	if best.IP.IsValid() {
		t.Fatal("expected zero-value result for empty collector")
	}
}

func TestTopNCollectorBestAfterUpdates(t *testing.T) {
	c := NewTopNCollector(3, false)
	c.Consider(TopResult{IP: addr("1.1.1.1"), ScoreMS: 100})
	c.Consider(TopResult{IP: addr("1.1.1.2"), ScoreMS: 200})
	c.Consider(TopResult{IP: addr("1.1.1.1"), ScoreMS: 50})

	best := c.Best()
	if best.IP != addr("1.1.1.1") || best.ScoreMS != 50 {
		t.Fatalf("expected 1.1.1.1/50ms, got %s/%.1fms", best.IP, best.ScoreMS)
	}
}

func TestTopNCollectorLargeInput(t *testing.T) {
	c := NewTopNCollector(10, false)
	for i := 0; i < 1000; i++ {
		ip := netip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(i >> 8), byte(i & 0xff)})
		c.Consider(TopResult{IP: ip, ScoreMS: math.Round(float64(i)*0.5*100) / 100})
	}
	if c.Len() != 10 {
		t.Fatalf("expected 10 results, got %d", c.Len())
	}
	snap := c.Snapshot()
	if len(snap) != 10 {
		t.Fatalf("expected 10 snapshots, got %d", len(snap))
	}
	for i := 1; i < len(snap); i++ {
		if snap[i].ScoreMS < snap[i-1].ScoreMS {
			t.Fatalf("snapshot not sorted at index %d", i)
		}
	}
}