package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"
)

type Config struct {
	Timeout              time.Duration
	SNI                  string
	HostHeader           string
	Path                 string
	Port                 int    // TLS port (default 443)
	Rounds               int   // 总测试次数，默认6
	SkipFirst            int   // 跳过前N次，默认1（跳过第1次握手）
	SkipFailedRounds     bool  // 跳过失败轮次（不中断探测）
	DialTimeout          time.Duration // TCP dial 超时，0 则使用 Timeout
	TLSHandshakeTimeout  time.Duration // TLS 握手超时，0 则使用 Timeout
	CloseConn            bool  // 每轮强制关闭连接（用于 HTTP jitter 测量）
	DisableHTTP2         bool  // 禁用 HTTP/2（用于 req.Close 生效）
}

type Result struct {
	IP        netip.Addr        `json:"ip"`
	OK        bool              `json:"ok"`
	Status    int               `json:"status"`
	Error     string            `json:"error,omitempty"`
	ConnectMS int64             `json:"connect_ms"`
	TLSMS     int64             `json:"tls_ms"`
	TTFBMS    int64             `json:"ttfb_ms"`
	TotalMS   int64             `json:"total_ms"`
	JitterMS  float64           `json:"jitter_ms"`
	MinMS     int64             `json:"min_ms"`
	MaxMS     int64             `json:"max_ms"`
	Trace     map[string]string `json:"trace,omitempty"`
	When      time.Time         `json:"when"`
}

type Prober struct {
	cfg    Config
	client *http.Client
}

// NewProber creates a reusable, direct-connection (no proxy) prober.
func NewProber(cfg Config) *Prober {
	if cfg.Path == "" {
		cfg.Path = "/cdn-cgi/trace"
	}
	if !strings.HasPrefix(cfg.Path, "/") {
		cfg.Path = "/" + cfg.Path
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}
	dialTimeout := cfg.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = cfg.Timeout
	}
	tlsTimeout := cfg.TLSHandshakeTimeout
	if tlsTimeout <= 0 {
		tlsTimeout = cfg.Timeout
	}
	if cfg.Port <= 0 {
		cfg.Port = 443
	}

	transport := &http.Transport{
		Proxy: nil, // critical: ignore HTTP(S)_PROXY and NO_PROXY env vars
		DialContext: (&net.Dialer{
			Timeout:   dialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     !cfg.DisableHTTP2,
		MaxIdleConns:          1024,
		MaxIdleConnsPerHost:   256,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   tlsTimeout,
		ResponseHeaderTimeout: cfg.Timeout,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			ServerName:         cfg.SNI,
			InsecureSkipVerify: true,
		},
	}
	if cfg.DisableHTTP2 {
		transport.TLSNextProto = make(map[string]func(authority string, c *tls.Conn) http.RoundTripper)
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
	}

	return &Prober{cfg: cfg, client: client}
}

// probeOnce performs a single HTTP probe request.
func (p *Prober) probeOnce(ctx context.Context, ip netip.Addr) Result {
	start := time.Now()
	res := Result{
		IP:   ip,
		When: start,
	}

	targetHost := ip.String()
	// URL host must wrap IPv6 in brackets.
	if ip.Is6() {
		targetHost = "[" + targetHost + "]"
	}

	port := p.cfg.Port
	if port <= 0 {
		port = 443
	}
	url := fmt.Sprintf("https://%s:%d%s", targetHost, port, p.cfg.Path)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		res.Error = err.Error()
		res.TotalMS = time.Since(start).Milliseconds()
		return res
	}
	if p.cfg.HostHeader != "" {
		req.Host = p.cfg.HostHeader
	}
	if p.cfg.CloseConn {
		req.Close = true
	}
	req.Header.Set("User-Agent", "vect/0.1")
	req.Header.Set("Accept", "text/plain")

	httpRes, err := p.client.Do(req)
	if err != nil {
		// Retry once on EOF: some CDN nodes close the connection immediately
		// after receiving a request on a newly established connection.
		if strings.Contains(err.Error(), "EOF") {
			fmt.Printf("PROBE RETRY %s -> %s: EOF (total=%dms)\n", ip.String(), p.cfg.HostHeader, time.Since(start).Milliseconds())
			req2, err2 := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err2 == nil {
				if p.cfg.HostHeader != "" {
					req2.Host = p.cfg.HostHeader
				}
				if p.cfg.CloseConn {
					req2.Close = true
				}
				req2.Header.Set("User-Agent", "vect/0.1")
				req2.Header.Set("Accept", "text/plain")
				httpRes, err = p.client.Do(req2)
			}
		}
		if err != nil {
			// Normalize common context timeout.
			if errors.Is(err, context.DeadlineExceeded) {
				res.Error = "timeout"
			} else {
				res.Error = err.Error()
			}
			fmt.Printf("PROBE ERR %s -> %s: %s (total=%dms) errtype=%T\n", ip.String(), p.cfg.HostHeader, res.Error, time.Since(start).Milliseconds(), err)
			res.TotalMS = time.Since(start).Milliseconds()
			return res
		}
	}
	defer func() { _ = httpRes.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(httpRes.Body, 64*1024))
	if err != nil {
		res.Error = fmt.Sprintf("read body: %v", err)
		res.TotalMS = time.Since(start).Milliseconds()
		return res
	}
	res.Status = httpRes.StatusCode
	res.TotalMS = time.Since(start).Milliseconds()
	res.OK = true

	if httpRes.StatusCode >= 200 && httpRes.StatusCode < 300 {
		res.Trace = parseTrace(string(body))
		fmt.Printf("PROBE OK %s -> %s: status=%d total=%dms\n", ip.String(), p.cfg.HostHeader, httpRes.StatusCode, time.Since(start).Milliseconds())
	} else {
		res.Error = fmt.Sprintf("http_status_%d", httpRes.StatusCode)
		fmt.Printf("PROBE BAD %s -> %s: status=%d total=%dms\n", ip.String(), p.cfg.HostHeader, httpRes.StatusCode, time.Since(start).Milliseconds())
	}
	return res
}

// ProbeHTTPTrace probes https://<ip>/<path> with SNI/HostHeader.
// This is a convenience wrapper that calls probeOnce for backward compatibility.
func (p *Prober) ProbeHTTPTrace(ctx context.Context, ip netip.Addr) Result {
	return p.probeOnce(ctx, ip)
}

// ProbeHTTPTraceMulti performs multiple probes and returns the average of rounds after skipping the first N.
// This avoids the TCP/TLS handshake overhead in the first request and provides more stable latency measurements.
func (p *Prober) ProbeHTTPTraceMulti(ctx context.Context, ip netip.Addr) Result {
	rounds := p.cfg.Rounds
	if rounds <= 0 {
		rounds = 6
	}
	skipFirst := p.cfg.SkipFirst
	if skipFirst < 0 {
		skipFirst = 1
	}

	var results []Result
	for i := 0; i < rounds; i++ {
		r := p.probeOnce(ctx, ip)
		results = append(results, r)
		if !r.OK && !p.cfg.SkipFailedRounds {
			return r
		}
	}

	return p.aggregateResults(results, ip, skipFirst)
}

func (p *Prober) aggregateResults(results []Result, ip netip.Addr, skipFirst int) Result {
	var allOK []Result
	for _, r := range results {
		if r.OK {
			allOK = append(allOK, r)
		}
	}
	if len(allOK) <= skipFirst {
		for _, r := range results {
			if r.OK {
				return r
			}
		}
		return results[len(results)-1]
	}
	validResults := allOK[skipFirst:]
	avg := calculateAverage(validResults, ip)
	jitterMS, minMS, maxMS := calculateJitter(validResults)
	avg.JitterMS = jitterMS
	avg.MinMS = minMS
	avg.MaxMS = maxMS
	fmt.Printf("AGGREGATE %s: total=%d ok=%d skipFirst=%d valid=%d\n", ip.String(), avg.TotalMS, len(allOK), skipFirst, len(validResults))
	return avg
}

// calculateAverage computes the average of multiple probe results.
func calculateAverage(results []Result, ip netip.Addr) Result {
	if len(results) == 0 {
		return Result{IP: ip, OK: false, Error: "no valid results"}
	}

	avg := Result{
		IP:   ip,
		OK:   true,
		When: results[0].When,
	}

	var totalConnectMS, totalTLSMS, totalTTFBMS, totalTotalMS int64
	var validConnect, validTLS, validTTFB int

	for _, r := range results {
		totalTotalMS += r.TotalMS
		if r.ConnectMS > 0 {
			totalConnectMS += r.ConnectMS
			validConnect++
		}
		if r.TLSMS > 0 {
			totalTLSMS += r.TLSMS
			validTLS++
		}
		if r.TTFBMS > 0 {
			totalTTFBMS += r.TTFBMS
			validTTFB++
		}
		// Use the status and trace from the last successful result
		avg.Status = r.Status
		avg.Trace = r.Trace
	}

	count := int64(len(results))
	avg.TotalMS = totalTotalMS / count

	if validConnect > 0 {
		avg.ConnectMS = totalConnectMS / int64(validConnect)
	}
	if validTLS > 0 {
		avg.TLSMS = totalTLSMS / int64(validTLS)
	}
	if validTTFB > 0 {
		avg.TTFBMS = totalTTFBMS / int64(validTTFB)
	}

	return avg
}

// calculateJitter computes the standard deviation, min, and max of TotalMS values.
// Uses sample standard deviation (N-1) and IQR-based outlier removal for robustness.
func calculateJitter(results []Result) (jitterMS float64, minMS int64, maxMS int64) {
	if len(results) == 0 {
		return 0, 0, 0
	}

	count := len(results)
	if count <= 1 {
		return 0, results[0].TotalMS, results[0].TotalMS
	}

	values := make([]int64, count)
	for i, r := range results {
		values[i] = r.TotalMS
	}
	sorted := make([]int64, count)
	copy(sorted, values)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	minMS = sorted[0]
	maxMS = sorted[count-1]

	q1 := sorted[count/4]
	q3 := sorted[3*count/4]
	iqr := q3 - q1
	lower := q1 - int64(float64(iqr)*1.5)
	upper := q3 + int64(float64(iqr)*1.5)

	var sum int64
	var validCount int
	var useAll bool
	for _, v := range values {
		if v >= lower && v <= upper {
			sum += v
			validCount++
		}
	}

	if validCount < 2 {
		useAll = true
		validCount = count
		sum = 0
		for _, v := range values {
			sum += v
		}
		lower = -1 << 63
		upper = 1<<63 - 1
	}

	mean := float64(sum) / float64(validCount)

	var sqDiff float64
	for _, v := range values {
		if useAll || (v >= lower && v <= upper) {
			d := float64(v) - mean
			sqDiff += d * d
		}
	}

	jitterMS = math.Sqrt(sqDiff / float64(validCount-1))
	return jitterMS, minMS, maxMS
}

func parseTrace(s string) map[string]string {
	m := make(map[string]string)
	lines := strings.Split(s, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k != "" {
			m[k] = v
		}
	}
	return m
}
