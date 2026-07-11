package engine

import (
	"testing"
	"time"

	"github.com/yu-929/Vect-IP/internal/probe"
)

func TestDefaultConfig(t *testing.T) {
	c := DefaultConfig()
	if c.Budget != 2000 {
		t.Errorf("Budget=2000 expected, got %d", c.Budget)
	}
	if c.TopN != 20 {
		t.Errorf("TopN=20 expected, got %d", c.TopN)
	}
	if c.Concurrency != 200 {
		t.Errorf("Concurrency=200 expected, got %d", c.Concurrency)
	}
	if c.Heads != 4 {
		t.Errorf("Heads=4 expected, got %d", c.Heads)
	}
	if c.Beam != 32 {
		t.Errorf("Beam=32 expected, got %d", c.Beam)
	}
	if c.DiversityWeight != 0.3 {
		t.Errorf("DiversityWeight=0.3 expected, got %f", c.DiversityWeight)
	}
	if c.SplitInterval != 20 {
		t.Errorf("SplitInterval=20 expected, got %d", c.SplitInterval)
	}
}

func TestConfigValidateOK(t *testing.T) {
	c := DefaultConfig()
	if err := c.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConfigValidateBudget(t *testing.T) {
	c := DefaultConfig()
	c.Budget = 0
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for Budget=0")
	}
	c.Budget = -1
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for Budget=-1")
	}
}

func TestConfigValidateTopN(t *testing.T) {
	c := DefaultConfig()
	c.TopN = 0
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for TopN=0")
	}
}

func TestConfigValidateConcurrency(t *testing.T) {
	c := DefaultConfig()
	c.Concurrency = 0
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for Concurrency=0")
	}
}

func TestConfigValidateHeads(t *testing.T) {
	c := DefaultConfig()
	c.Heads = 0
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for Heads=0")
	}
}

func TestConfigValidateBeam(t *testing.T) {
	c := DefaultConfig()
	c.Beam = 0
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for Beam=0")
	}
}

func TestConfigValidateSplitStepV4(t *testing.T) {
	c := DefaultConfig()
	c.SplitStepV4 = 0
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for SplitStepV4=0")
	}
	c.SplitStepV4 = 9
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for SplitStepV4=9")
	}
}

func TestConfigValidateSplitStepV6(t *testing.T) {
	c := DefaultConfig()
	c.SplitStepV6 = 0
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for SplitStepV6=0")
	}
	c.SplitStepV6 = 17
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for SplitStepV6=17")
	}
}

func TestConfigValidateMinSamplesSplit(t *testing.T) {
	c := DefaultConfig()
	c.MinSamplesSplit = 0
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for MinSamplesSplit=0")
	}
}

func TestConfigValidateMaxBitsV4(t *testing.T) {
	c := DefaultConfig()
	c.MaxBitsV4 = 0
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for MaxBitsV4=0")
	}
	c.MaxBitsV4 = 33
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for MaxBitsV4=33")
	}
}

func TestConfigValidateMaxBitsV6(t *testing.T) {
	c := DefaultConfig()
	c.MaxBitsV6 = 0
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for MaxBitsV6=0")
	}
	c.MaxBitsV6 = 129
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for MaxBitsV6=129")
	}
}

func TestConfigValidateDiversityWeight(t *testing.T) {
	c := DefaultConfig()
	c.DiversityWeight = -0.1
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for DiversityWeight=-0.1")
	}
	c.DiversityWeight = 1.1
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for DiversityWeight=1.1")
	}
}

func TestConfigValidateColoBoth(t *testing.T) {
	c := DefaultConfig()
	c.ColoAllow = []string{"HKG"}
	c.ColoBlock = []string{"LAX"}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for both allow and block")
	}
}

func TestConfigApplyDefaults(t *testing.T) {
	c := Config{}
	c.ApplyDefaults()
	defaults := DefaultConfig()
	if c.Budget != defaults.Budget {
		t.Errorf("Budget=%d expected %d", c.Budget, defaults.Budget)
	}
	if c.TopN != defaults.TopN {
		t.Errorf("TopN=%d expected %d", c.TopN, defaults.TopN)
	}
	if c.Concurrency != defaults.Concurrency {
		t.Errorf("Concurrency=%d expected %d", c.Concurrency, defaults.Concurrency)
	}
	if c.Heads != defaults.Heads {
		t.Errorf("Heads=%d expected %d", c.Heads, defaults.Heads)
	}
	if c.Beam != defaults.Beam {
		t.Errorf("Beam=%d expected %d", c.Beam, defaults.Beam)
	}
	if c.SplitStepV4 != defaults.SplitStepV4 {
		t.Errorf("SplitStepV4=%d expected %d", c.SplitStepV4, defaults.SplitStepV4)
	}
	if c.SplitStepV6 != defaults.SplitStepV6 {
		t.Errorf("SplitStepV6=%d expected %d", c.SplitStepV6, defaults.SplitStepV6)
	}
	if c.MinSamplesSplit != defaults.MinSamplesSplit {
		t.Errorf("MinSamplesSplit=%d expected %d", c.MinSamplesSplit, defaults.MinSamplesSplit)
	}
	if c.MaxBitsV4 != defaults.MaxBitsV4 {
		t.Errorf("MaxBitsV4=%d expected %d", c.MaxBitsV4, defaults.MaxBitsV4)
	}
	if c.MaxBitsV6 != defaults.MaxBitsV6 {
		t.Errorf("MaxBitsV6=%d expected %d", c.MaxBitsV6, defaults.MaxBitsV6)
	}
	if c.SplitInterval != defaults.SplitInterval {
		t.Errorf("SplitInterval=%d expected %d", c.SplitInterval, defaults.SplitInterval)
	}
	if c.DiversityWeight != defaults.DiversityWeight {
		t.Errorf("DiversityWeight=%f expected %f", c.DiversityWeight, defaults.DiversityWeight)
	}
}

func TestConfigApplyDefaultsPreservesSet(t *testing.T) {
	c := Config{Budget: 100, TopN: 5}
	c.ApplyDefaults()
	if c.Budget != 100 {
		t.Errorf("Budget should be preserved as 100, got %d", c.Budget)
	}
	if c.TopN != 5 {
		t.Errorf("TopN should be preserved as 5, got %d", c.TopN)
	}
	if c.Concurrency != 200 {
		t.Errorf("Concurrency should be defaulted to 200, got %d", c.Concurrency)
	}
}

func TestConfigToTreeConfig(t *testing.T) {
	c := DefaultConfig()
	tc := c.ToTreeConfig()
	if tc.SplitStepV4 != c.SplitStepV4 {
		t.Errorf("SplitStepV4 mismatch")
	}
	if tc.MaxBitsV4 != c.MaxBitsV4 {
		t.Errorf("MaxBitsV4 mismatch")
	}
	if tc.MinSamples != c.MinSamplesSplit {
		t.Errorf("MinSamples mismatch")
	}
}

func TestConfigToHeadManagerConfig(t *testing.T) {
	c := DefaultConfig()
	hc := c.ToHeadManagerConfig(3000)
	if hc.NumHeads != c.Heads {
		t.Errorf("NumHeads mismatch")
	}
	if hc.TimeoutMS != 3000 {
		t.Errorf("TimeoutMS=3000 expected, got %f", hc.TimeoutMS)
	}
	if hc.BaseSeed != c.Seed {
		t.Errorf("BaseSeed mismatch")
	}
	if hc.HistorySize != c.Beam {
		t.Errorf("HistorySize mismatch")
	}
	if hc.RepulsionDecay != 0.5 {
		t.Errorf("RepulsionDecay=0.5 expected, got %f", hc.RepulsionDecay)
	}
}

func TestRequestTimeoutMS(t *testing.T) {
	r := &Request{}
	ms := r.TimeoutMS()
	if ms != 3000 {
		t.Errorf("default timeout=3000 expected, got %f", ms)
	}
	r.Probe = probe.Config{Timeout: 5 * time.Second}
	ms = r.TimeoutMS()
	if ms != 5000 {
		t.Errorf("timeout=5000 expected, got %f", ms)
	}
}

func TestNew(t *testing.T) {
	cfg := DefaultConfig()
	e := New(cfg, probe.Config{})
	if e == nil {
		t.Fatal("New returned nil")
	}
	if e.cfg.Budget != cfg.Budget {
		t.Errorf("Budget mismatch")
	}
	if e.cfg.Concurrency != cfg.Concurrency {
		t.Errorf("Concurrency mismatch")
	}
}

func TestNewWithZeroConfig(t *testing.T) {
	e := New(Config{}, probe.Config{})
	if e == nil {
		t.Fatal("New returned nil")
	}
	if e.cfg.Budget != 2000 {
		t.Errorf("expected Budget=2000 after ApplyDefaults, got %d", e.cfg.Budget)
	}
}