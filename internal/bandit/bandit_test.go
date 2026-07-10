package bandit

import (
	"math"
	"net/netip"
	"testing"
)

func TestNewArmNode(t *testing.T) {
	prefix := netip.MustParsePrefix("1.1.1.0/24")
	node := NewArmNode(prefix, nil)

	if node.Prefix != prefix {
		t.Errorf("expected prefix %s, got %s", prefix, node.Prefix)
	}
	if node.Alpha != 1.0 || node.Beta != 1.0 {
		t.Errorf("expected uniform Beta prior, got Alpha=%f Beta=%f", node.Alpha, node.Beta)
	}
	if node.Samples != 0 {
		t.Errorf("expected 0 samples, got %d", node.Samples)
	}
	if node.IsSplit {
		t.Error("expected IsSplit=false")
	}
}

func TestArmNodeUpdateSuccess(t *testing.T) {
	node := NewArmNode(netip.MustParsePrefix("1.1.1.0/24"), nil)
	node.Update(true, 100, 3000)

	if node.Samples != 1 {
		t.Errorf("expected 1 sample, got %d", node.Samples)
	}
	if node.Successes != 1 {
		t.Errorf("expected 1 success, got %d", node.Successes)
	}
	if node.Alpha != 2.0 {
		t.Errorf("expected Alpha=2.0, got %f", node.Alpha)
	}

	stats := node.Stats()
	if stats.MeanLatency < 99 || stats.MeanLatency > 101 {
		t.Errorf("expected mean latency ~100, got %f", stats.MeanLatency)
	}
}

func TestArmNodeUpdateFailure(t *testing.T) {
	node := NewArmNode(netip.MustParsePrefix("1.1.1.0/24"), nil)
	node.Update(false, 0, 3000)

	if node.Samples != 1 {
		t.Errorf("expected 1 sample, got %d", node.Samples)
	}
	if node.Failures != 1 {
		t.Errorf("expected 1 failure, got %d", node.Failures)
	}
	if node.Beta != 2.0 {
		t.Errorf("expected Beta=2.0, got %f", node.Beta)
	}
}

func TestArmNodeCanSplit(t *testing.T) {
	node := NewArmNode(netip.MustParsePrefix("1.1.0.0/16"), nil)

	// Not enough samples
	if node.CanSplit(5, 24, 56) {
		t.Error("expected CanSplit=false with 0 samples")
	}

	// Add enough samples
	for i := 0; i < 5; i++ {
		node.Update(true, 100, 3000)
	}

	if !node.CanSplit(5, 24, 56) {
		t.Error("expected CanSplit=true with 5 samples")
	}

	// Already at max bits
	node2 := NewArmNode(netip.MustParsePrefix("1.1.1.0/24"), nil)
	for i := 0; i < 5; i++ {
		node2.Update(true, 100, 3000)
	}
	if node2.CanSplit(5, 24, 56) {
		t.Error("expected CanSplit=false at max bits")
	}
}

func TestArmNodeInformationGain(t *testing.T) {
	node := NewArmNode(netip.MustParsePrefix("1.1.0.0/16"), nil)

	// No samples => infinite gain
	ig := node.InformationGain()
	if !math.IsInf(ig, 1) {
		t.Errorf("expected +Inf for unexplored arm, got %f", ig)
	}

	// After some samples, gain should be finite
	node.Update(true, 100, 3000)
	ig = node.InformationGain()
	if math.IsInf(ig, 1) || ig < 0 {
		t.Errorf("expected finite positive gain, got %f", ig)
	}
}

func TestArmTreeNew(t *testing.T) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("1.1.0.0/16"),
		netip.MustParsePrefix("1.2.0.0/16"),
	}
	tree := NewArmTree(prefixes, DefaultTreeConfig())

	if tree.Size() != 2 {
		t.Errorf("expected 2 roots, got %d", tree.Size())
	}
}

func TestArmTreeGetOrCreateNode(t *testing.T) {
	prefixes := []netip.Prefix{netip.MustParsePrefix("1.1.0.0/16")}
	tree := NewArmTree(prefixes, DefaultTreeConfig())

	// Get existing
	node := tree.GetOrCreateNode(netip.MustParsePrefix("1.1.0.0/16"))
	if node == nil {
		t.Fatal("expected non-nil node")
	}

	// Create new child
	child := tree.GetOrCreateNode(netip.MustParsePrefix("1.1.1.0/24"))
	if child == nil {
		t.Fatal("expected non-nil child node")
	}
	if child.Parent != node {
		t.Error("expected parent to be the /16 node")
	}
}

func TestArmTreeSplitNode(t *testing.T) {
	prefixes := []netip.Prefix{netip.MustParsePrefix("1.1.0.0/16")}
	tree := NewArmTree(prefixes, TreeConfig{
		SplitStepV4: 2,
		SplitStepV6: 4,
		MaxBitsV4:   24,
		MaxBitsV6:   56,
		MinSamples:  3,
	})

	node := tree.GetOrCreateNode(netip.MustParsePrefix("1.1.0.0/16"))
	// Add enough samples
	for i := 0; i < 3; i++ {
		node.Update(true, 100, 3000)
	}

	children := tree.SplitNode(node)
	if children == nil {
		t.Fatal("expected children from split")
	}
	if len(children) != 4 {
		t.Errorf("expected 4 children (2^2), got %d", len(children))
	}

	// Node should be marked as split
	if !node.IsSplit {
		t.Error("expected node.IsSplit=true after split")
	}

	// Can't split again
	if tree.SplitNode(node) != nil {
		t.Error("expected nil for already split node")
	}
}

func TestArmTreeLeafNodes(t *testing.T) {
	prefixes := []netip.Prefix{netip.MustParsePrefix("1.1.0.0/16")}
	tree := NewArmTree(prefixes, DefaultTreeConfig())

	leaves := tree.LeafNodes()
	if len(leaves) != 1 {
		t.Errorf("expected 1 leaf, got %d", len(leaves))
	}
}

func TestArmTreeUpdate(t *testing.T) {
	prefixes := []netip.Prefix{netip.MustParsePrefix("1.1.0.0/16")}
	tree := NewArmTree(prefixes, DefaultTreeConfig())

	tree.Update(netip.MustParsePrefix("1.1.0.0/16"), true, 100, 3000)

	node := tree.GetNode(netip.MustParsePrefix("1.1.0.0/16"))
	if node == nil {
		t.Fatal("expected non-nil node")
	}
	stats := node.Stats()
	if stats.Samples != 1 {
		t.Errorf("expected 1 sample, got %d", stats.Samples)
	}
}

func TestThompsonSamplerNew(t *testing.T) {
	ts := NewThompsonSampler(42, 3000)
	if ts == nil {
		t.Fatal("expected non-nil sampler")
	}
	if ts.timeoutMS != 3000 {
		t.Errorf("expected timeout 3000, got %f", ts.timeoutMS)
	}
}

func TestThompsonSamplerSampleScoreUnexplored(t *testing.T) {
	ts := NewThompsonSampler(42, 3000)
	node := NewArmNode(netip.MustParsePrefix("1.1.0.0/16"), nil)

	score := ts.SampleScore(node)
	// Unexplored nodes should get optimistic score between 0 and 1500
	if score < 0 || score > 1500 {
		t.Errorf("expected optimistic score [0,1500], got %f", score)
	}
}

func TestThompsonSamplerSampleScoreExplored(t *testing.T) {
	ts := NewThompsonSampler(42, 3000)
	node := NewArmNode(netip.MustParsePrefix("1.1.0.0/16"), nil)

	// Add enough samples to avoid optimistic initialization
	for i := 0; i < 5; i++ {
		node.Update(true, 100, 3000)
	}

	score := ts.SampleScore(node)
	if score < 0 {
		t.Errorf("expected positive score, got %f", score)
	}
}

func TestThompsonSamplerSampleIP(t *testing.T) {
	ts := NewThompsonSampler(42, 3000)

	// IPv4
	prefix := netip.MustParsePrefix("1.1.0.0/16")
	ip := ts.SampleIP(prefix)
	if !prefix.Contains(ip) {
		t.Errorf("sampled IP %s outside prefix %s", ip, prefix)
	}

	// IPv6
	prefix6 := netip.MustParsePrefix("2606:4700::/32")
	ip6 := ts.SampleIP(prefix6)
	if !prefix6.Contains(ip6) {
		t.Errorf("sampled IP %s outside prefix %s", ip6, prefix6)
	}
}

func TestThompsonSamplerDeterministic(t *testing.T) {
	ts1 := NewThompsonSampler(42, 3000)
	ts2 := NewThompsonSampler(42, 3000)

	prefix := netip.MustParsePrefix("1.1.0.0/16")

	for i := 0; i < 10; i++ {
		ip1 := ts1.SampleIP(prefix)
		ip2 := ts2.SampleIP(prefix)
		if ip1 != ip2 {
			t.Errorf("expected deterministic sampling, got %s vs %s", ip1, ip2)
		}
	}
}

func TestSearchHeadNew(t *testing.T) {
	head := NewSearchHead(0, 42, 3000, 32)
	if head.ID != 0 {
		t.Errorf("expected ID=0, got %d", head.ID)
	}
	if head.Sampler == nil {
		t.Error("expected non-nil sampler")
	}
}

func TestSearchHeadSetFocus(t *testing.T) {
	head := NewSearchHead(0, 42, 3000, 32)
	prefix := netip.MustParsePrefix("1.1.0.0/16")

	head.SetFocus(prefix)
	if head.GetFocus() != prefix {
		t.Errorf("expected focus %s, got %s", prefix, head.GetFocus())
	}

	// History should contain the prefix
	history := head.GetHistory()
	if len(history) != 1 || history[0] != prefix {
		t.Errorf("expected history [%s], got %v", prefix, history)
	}
}

func TestHeadManagerNew(t *testing.T) {
	cfg := HeadManagerConfig{
		NumHeads:        4,
		TimeoutMS:       3000,
		BaseSeed:        0,
		HistorySize:     32,
		DiversityWeight: 0.3,
		RepulsionDecay:  0.5,
	}
	mgr := NewHeadManager(cfg)

	if mgr.NumHeads() != 4 {
		t.Errorf("expected 4 heads, got %d", mgr.NumHeads())
	}

	for i := 0; i < 4; i++ {
		head := mgr.GetHead(i)
		if head == nil {
			t.Errorf("expected non-nil head at %d", i)
		}
	}
}

func TestHeadManagerGetHeadInvalid(t *testing.T) {
	cfg := DefaultHeadManagerConfig()
	cfg.NumHeads = 2
	mgr := NewHeadManager(cfg)

	if mgr.GetHead(-1) != nil {
		t.Error("expected nil for negative index")
	}
	if mgr.GetHead(5) != nil {
		t.Error("expected nil for out-of-range index")
	}
}

func TestPrefixDistance(t *testing.T) {
	a := netip.MustParsePrefix("1.1.0.0/16")
	b := netip.MustParsePrefix("1.1.0.0/16")

	// Same prefix
	if d := prefixDistance(a, b); d != 0 {
		t.Errorf("expected distance 0, got %d", d)
	}

	// Different address family
	c := netip.MustParsePrefix("2606:4700::/32")
	if d := prefixDistance(a, c); d != 128 {
		t.Errorf("expected distance 128 for different families, got %d", d)
	}

	// Slightly different
	d := netip.MustParsePrefix("1.2.0.0/16")
	if d := prefixDistance(a, d); d <= 0 || d > 16 {
		t.Errorf("expected distance in (0,16], got %d", d)
	}
}

func TestArmStatsScore(t *testing.T) {
	stats := ArmStats{
		Samples:     10,
		Successes:   9,
		Failures:    1,
		MeanLatency: 100,
		SuccessRate: 0.9,
	}

	score := stats.Score(3000)
	expected := 100 + (1-0.9)*3000 // 400
	if math.Abs(score-expected) > 0.1 {
		t.Errorf("expected score ~%f, got %f", expected, score)
	}
}

func TestArmStatsScoreNoSamples(t *testing.T) {
	stats := ArmStats{
		Samples: 0,
	}

	score := stats.Score(3000)
	if score != 6000 {
		t.Errorf("expected score 6000 (2*timeout), got %f", score)
	}
}

func TestGetSplitCandidates(t *testing.T) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("1.1.0.0/16"),
		netip.MustParsePrefix("1.2.0.0/16"),
	}
	tree := NewArmTree(prefixes, TreeConfig{
		SplitStepV4: 2,
		SplitStepV6: 4,
		MaxBitsV4:   24,
		MaxBitsV6:   56,
		MinSamples:  3,
	})

	// Add samples to one prefix
	node1 := tree.GetOrCreateNode(netip.MustParsePrefix("1.1.0.0/16"))
	for i := 0; i < 5; i++ {
		node1.Update(true, 100, 3000)
	}

	candidates := tree.GetSplitCandidates(10)
	if len(candidates) == 0 {
		t.Error("expected at least 1 candidate")
	}
}

func TestRebalanceHeads(t *testing.T) {
	prefixes := []netip.Prefix{netip.MustParsePrefix("1.1.0.0/16")}
	tree := NewArmTree(prefixes, DefaultTreeConfig())

	cfg := DefaultHeadManagerConfig()
	cfg.NumHeads = 2
	mgr := NewHeadManager(cfg)

	// Set both heads to the same focus
	prefix := netip.MustParsePrefix("1.1.0.0/16")
	mgr.GetHead(0).SetFocus(prefix)
	mgr.GetHead(1).SetFocus(prefix)

	// Rebalance should spread them out
	mgr.RebalanceHeads(tree)

	// After rebalance, heads should still have valid focus
	f0 := mgr.GetHead(0).GetFocus()
	f1 := mgr.GetHead(1).GetFocus()
	if !f0.IsValid() || !f1.IsValid() {
		t.Error("expected valid focuses after rebalance")
	}
}