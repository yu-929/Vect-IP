package probe

import (
	"net/netip"
	"testing"
	"time"
)

func TestParseTraceSingle(t *testing.T) {
	m := parseTrace("key=value")
	if m["key"] != "value" {
		t.Fatalf("expected value, got %s", m["key"])
	}
}

func TestParseTraceMultiple(t *testing.T) {
	input := "ip=1.1.1.1\ncolo=HKG\nloc=Hong Kong\ntls=TLSv1.3"
	m := parseTrace(input)
	tests := []struct {
		key, want string
	}{
		{"ip", "1.1.1.1"},
		{"colo", "HKG"},
		{"loc", "Hong Kong"},
		{"tls", "TLSv1.3"},
	}
	for _, tt := range tests {
		if got := m[tt.key]; got != tt.want {
			t.Errorf("parseTrace(%q) = %q, want %q", tt.key, got, tt.want)
		}
	}
}

func TestParseTraceSkipsEmptyLines(t *testing.T) {
	input := "a=1\n\nb=2\n  \nc=3"
	m := parseTrace(input)
	if len(m) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(m))
	}
}

func TestParseTraceSkipsNoEquals(t *testing.T) {
	input := "a=1\nbadsyntax\nc=3"
	m := parseTrace(input)
	if len(m) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(m))
	}
	if m["a"] != "1" || m["c"] != "3" {
		t.Fatal("skipped valid entries")
	}
}

func TestParseTraceTrimsWhitespace(t *testing.T) {
	input := "  key  =  value  "
	m := parseTrace(input)
	if m["key"] != "value" {
		t.Fatalf("expected value, got %q", m["key"])
	}
}

func TestParseTraceSkipsEmptyKey(t *testing.T) {
	input := "=value"
	m := parseTrace(input)
	if len(m) != 0 {
		t.Fatal("expected empty map for empty key")
	}
}

func TestParseTraceRealistic(t *testing.T) {
	input := `ts=1712345678
ip=1.1.1.1
colo=LAX
loc=Los+Angeles
tls=TLSv1.3
sni=off
http=http/2
visit_scheme=https
uag=Mozilla/5.0
colo=LAX
sliver=none
http=http/2
loc=Los+Angeles
tls=TLSv1.3
`
	m := parseTrace(input)
	if m["ip"] != "1.1.1.1" {
		t.Errorf("ip=%q, want 1.1.1.1", m["ip"])
	}
	if m["colo"] != "LAX" {
		t.Errorf("colo=%q, want LAX", m["colo"])
	}
	if m["loc"] != "Los+Angeles" {
		t.Errorf("loc=%q, want Los+Angeles", m["loc"])
	}
	if m["tls"] != "TLSv1.3" {
		t.Errorf("tls=%q, want TLSv1.3", m["tls"])
	}
}

func TestCalculateAverageEmpty(t *testing.T) {
	ip := netip.MustParseAddr("1.1.1.1")
	r := calculateAverage(nil, ip)
	if r.OK {
		t.Fatal("expected OK=false for empty input")
	}
	if r.Error != "no valid results" {
		t.Fatalf("expected 'no valid results', got %q", r.Error)
	}
}

func TestCalculateAverageSingle(t *testing.T) {
	ip := netip.MustParseAddr("1.1.1.1")
	results := []Result{{
		IP: ip, OK: true, TotalMS: 100,
		ConnectMS: 10, TLSMS: 20, TTFBMS: 30,
	}}
	r := calculateAverage(results, ip)
	if !r.OK {
		t.Fatal("expected OK=true")
	}
	if r.TotalMS != 100 {
		t.Fatalf("expected TotalMS=100, got %d", r.TotalMS)
	}
	if r.ConnectMS != 10 {
		t.Fatalf("expected ConnectMS=10, got %d", r.ConnectMS)
	}
	if r.TLSMS != 20 {
		t.Fatalf("expected TLSMS=20, got %d", r.TLSMS)
	}
	if r.TTFBMS != 30 {
		t.Fatalf("expected TTFBMS=30, got %d", r.TTFBMS)
	}
}

func TestCalculateAverageMultiple(t *testing.T) {
	ip := netip.MustParseAddr("1.1.1.1")
	results := []Result{
		{IP: ip, OK: true, TotalMS: 100, ConnectMS: 10, TLSMS: 20, TTFBMS: 30},
		{IP: ip, OK: true, TotalMS: 200, ConnectMS: 20, TLSMS: 40, TTFBMS: 60},
	}
	r := calculateAverage(results, ip)
	if !r.OK {
		t.Fatal("expected OK=true")
	}
	if r.TotalMS != 150 {
		t.Fatalf("expected TotalMS=150, got %d", r.TotalMS)
	}
	if r.ConnectMS != 15 {
		t.Fatalf("expected ConnectMS=15, got %d", r.ConnectMS)
	}
	if r.TLSMS != 30 {
		t.Fatalf("expected TLSMS=30, got %d", r.TLSMS)
	}
	if r.TTFBMS != 45 {
		t.Fatalf("expected TTFBMS=45, got %d", r.TTFBMS)
	}
}

func TestCalculateAverageSkipsZeroMS(t *testing.T) {
	ip := netip.MustParseAddr("1.1.1.1")
	results := []Result{
		{IP: ip, OK: true, TotalMS: 100, ConnectMS: 0, TLSMS: 20, TTFBMS: 30},
		{IP: ip, OK: true, TotalMS: 200, ConnectMS: 10, TLSMS: 0, TTFBMS: 60},
	}
	r := calculateAverage(results, ip)
	if r.TotalMS != 150 {
		t.Fatalf("expected TotalMS=150, got %d", r.TotalMS)
	}
	if r.ConnectMS != 10 {
		t.Fatalf("expected ConnectMS=10 (avg of 1 valid), got %d", r.ConnectMS)
	}
	if r.TLSMS != 20 {
		t.Fatalf("expected TLSMS=20 (avg of 1 valid), got %d", r.TLSMS)
	}
	if r.TTFBMS != 45 {
		t.Fatalf("expected TTFBMS=45, got %d", r.TTFBMS)
	}
}

func TestCalculateAverageUsesLastStatus(t *testing.T) {
	ip := netip.MustParseAddr("1.1.1.1")
	results := []Result{
		{IP: ip, OK: true, Status: 200, TotalMS: 100},
		{IP: ip, OK: true, Status: 404, TotalMS: 200},
	}
	r := calculateAverage(results, ip)
	if r.Status != 404 {
		t.Fatalf("expected Status=404 (last), got %d", r.Status)
	}
}

func TestCalculateAverageUsesLastTrace(t *testing.T) {
	ip := netip.MustParseAddr("1.1.1.1")
	results := []Result{
		{IP: ip, OK: true, TotalMS: 100, Trace: map[string]string{"colo": "HKG"}},
		{IP: ip, OK: true, TotalMS: 200, Trace: map[string]string{"colo": "LAX"}},
	}
	r := calculateAverage(results, ip)
	if r.Trace["colo"] != "LAX" {
		t.Fatalf("expected colo=LAX from last result, got %s", r.Trace["colo"])
	}
}

func TestNewProber(t *testing.T) {
	cfg := Config{Timeout: 3 * time.Second, Path: "/cdn-cgi/trace", Port: 443}
	p := NewProber(cfg)
	if p == nil {
		t.Fatal("NewProber returned nil")
	}
	if p.cfg.Port != 443 {
		t.Errorf("expected Port=443, got %d", p.cfg.Port)
	}
	if p.cfg.Path != "/cdn-cgi/trace" {
		t.Errorf("expected Path=/cdn-cgi/trace, got %s", p.cfg.Path)
	}
}

func TestNewProberDefaults(t *testing.T) {
	p := NewProber(Config{})
	if p == nil {
		t.Fatal("NewProber returned nil")
	}
	if p.cfg.Port != 443 {
		t.Errorf("expected Port=443, got %d", p.cfg.Port)
	}
	if p.cfg.Path != "/cdn-cgi/trace" {
		t.Errorf("expected Path=/cdn-cgi/trace, got %s", p.cfg.Path)
	}
	if p.cfg.Timeout != 3*time.Second {
		t.Errorf("expected Timeout=3s, got %v", p.cfg.Timeout)
	}
}

func TestNewDownloadProber(t *testing.T) {
	cfg := DownloadConfig{Timeout: 30000, Bytes: 10000000}
	p := NewDownloadProber(cfg)
	if p == nil {
		t.Fatal("NewDownloadProber returned nil")
	}
	if p.cfg.Bytes != 10000000 {
		t.Errorf("expected Bytes=10000000, got %d", p.cfg.Bytes)
	}
}

func TestNewDownloadProberDefaults(t *testing.T) {
	p := NewDownloadProber(DownloadConfig{})
	if p == nil {
		t.Fatal("NewDownloadProber returned nil")
	}
	if p.cfg.Timeout != 45*time.Second {
		t.Errorf("expected Timeout=45s, got %v", p.cfg.Timeout)
	}
	if p.cfg.HostName != "speed.cloudflare.com" {
		t.Errorf("expected HostName=speed.cloudflare.com, got %s", p.cfg.HostName)
	}
}