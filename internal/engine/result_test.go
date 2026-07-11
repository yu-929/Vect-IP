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
	c := NewTopNCollector(5)
	if c.n != 5 {
		t.Fatalf("expected n=5, got %d", c.n)
	}
	if c.Len() != 0 {
		t.Fatalf("expected empty, got %d", c.Len())
	}
}

func TestTopNCollectorZero(t *testing.T) {
	c := NewTopNCollector(0)
	c.Consider(TopResult{IP: addr("1.1.1.1"), ScoreMS: 10})
	if c.Len() != 0 {
		t.Fatal("expected no results for n=0")
	}
}

func TestTopNCollectorConsider(t *testing.T) {
	c := NewTopNCollector(3)
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
	c := NewTopNCollector(2)
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
	c := NewTopNCollector(3)
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
	c := NewTopNCollector(3)
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
	c := NewTopNCollector(5)
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
	c := NewTopNCollector(3)
	best := c.Best()
	if best.IP.IsValid() {
		t.Fatal("expected zero-value result for empty collector")
	}
}

func TestTopNCollectorBestAfterUpdates(t *testing.T) {
	c := NewTopNCollector(3)
	c.Consider(TopResult{IP: addr("1.1.1.1"), ScoreMS: 100})
	c.Consider(TopResult{IP: addr("1.1.1.2"), ScoreMS: 200})
	c.Consider(TopResult{IP: addr("1.1.1.1"), ScoreMS: 50})

	best := c.Best()
	if best.IP != addr("1.1.1.1") || best.ScoreMS != 50 {
		t.Fatalf("expected 1.1.1.1/50ms, got %s/%.1fms", best.IP, best.ScoreMS)
	}
}

func TestTopNCollectorLargeInput(t *testing.T) {
	c := NewTopNCollector(10)
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