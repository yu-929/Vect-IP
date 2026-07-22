// Package probe implements TCP/ICMP probe, bandwidth download and traceroute.
package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"
)

type DownloadConfig struct {
	Timeout time.Duration
	Bytes   int64
	SNI      string
	HostName string
	Path     string
	// CustomURL indicates the user supplied a custom download URL.
	// When true, the Path is used as-is (no "?bytes=N" appended).
	CustomURL bool
}

type DownloadResult struct {
	IP          netip.Addr `json:"ip"`
	OK          bool       `json:"ok"`
	Status      int        `json:"status"`
	Error       string     `json:"error,omitempty"`
	Bytes       int64      `json:"bytes"`
	TotalMS     int64      `json:"total_ms"`
	Mbps        float64    `json:"mbps"`
	PeakMbps    float64    `json:"peak_mbps"`
	BaselineRTT float64    `json:"baseline_rtt"`
	InflightRTT float64    `json:"inflight_rtt"`
	Streams     int        `json:"streams"`
	When        time.Time  `json:"when"`
}

type DownloadProber struct {
	cfg    DownloadConfig
	client *http.Client
}

func NewDownloadProber(cfg DownloadConfig) *DownloadProber {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 45 * time.Second
	}
	// Default endpoint needs ?bytes=N in URL; custom URL can use Bytes==0 for "no limit".
	if cfg.Bytes <= 0 && !cfg.CustomURL {
		cfg.Bytes = 50_000_000
	}
	if cfg.SNI == "" {
		cfg.SNI = "speed.cloudflare.com"
	}
	if cfg.HostName == "" {
		cfg.HostName = "speed.cloudflare.com"
	}
	if cfg.Path == "" {
		cfg.Path = "/__down"
	}

	transport := &http.Transport{
		Proxy: nil, // critical: ignore HTTP(S)_PROXY and NO_PROXY env vars
		DialContext: (&net.Dialer{
			Timeout:   cfg.Timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			ServerName: cfg.SNI,
		},
	}

	return &DownloadProber{
		cfg: cfg,
		client: &http.Client{
			Transport: transport,
			Timeout:   cfg.Timeout,
		},
	}
}

func (p *DownloadProber) measureRTT(ctx context.Context, host string) float64 {
	url := "https://" + host + "/cdn-cgi/trace"
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return 0
	}
	req.Host = p.cfg.HostName
	start := time.Now()
	resp, err := p.client.Do(req)
	if err != nil {
		return 0
	}
	_ = resp.Body.Close()
	return float64(time.Since(start).Microseconds()) / 1000.0
}

func (p *DownloadProber) Download(ctx context.Context, ip netip.Addr) DownloadResult {
	start := time.Now()
	out := DownloadResult{
		IP:      ip,
		When:    start,
		Streams: 1,
	}

	host := ip.String()
	if ip.Is6() {
		host = "[" + host + "]"
	}

	// Baseline RTT before download
	out.BaselineRTT = p.measureRTT(ctx, host)

	var url string
	if p.cfg.CustomURL {
		url = "https://" + host + p.cfg.Path
	} else {
		url = "https://" + host + p.cfg.Path + "?bytes=" + strconv.FormatInt(p.cfg.Bytes, 10)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		out.Error = err.Error()
		out.TotalMS = time.Since(start).Milliseconds()
		return out
	}
	req.Host = p.cfg.HostName
	req.Header.Set("User-Agent", "vect/0.1")
	req.Header.Set("Accept", "application/octet-stream")

	resp, err := p.client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			out.Error = "timeout"
		} else {
			out.Error = err.Error()
		}
		out.TotalMS = time.Since(start).Milliseconds()
		return out
	}
	defer func() { _ = resp.Body.Close() }()

	out.Status = resp.StatusCode
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		io.Copy(io.Discard, resp.Body)
		out.Error = fmt.Sprintf("http_status_%d", resp.StatusCode)
		out.TotalMS = time.Since(start).Milliseconds()
		return out
	}

	// Inflight RTT measurement: fire after 500ms in a goroutine
	inflightCh := make(chan float64, 1)
	go func() {
		time.Sleep(500 * time.Millisecond)
		inflightCh <- p.measureRTT(ctx, host)
	}()

	var n int64
	buf := make([]byte, 64*1024)
	peakStart := time.Now()
	peakBytes := int64(0)
	peakMbps := 0.0
	recordPeak := func() {
		seg := time.Since(peakStart)
		if seg > 50*time.Millisecond && peakBytes > 0 {
			m := (float64(peakBytes) * 8) / seg.Seconds() / 1e6
			if m > peakMbps {
				peakMbps = m
			}
		}
	}
	readFn := func() error {
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			now := time.Now()
			afterPeak := now.Sub(peakStart)
			if afterPeak >= 200*time.Millisecond {
				recordPeak()
				peakStart = now
				peakBytes = 0
			}
			limit := p.cfg.Bytes
			if limit > 0 && n >= limit {
				return nil
			}
			maxRead := len(buf)
			if limit > 0 && n+int64(maxRead) > limit {
				maxRead = int(limit - n)
			}
			nr, er := resp.Body.Read(buf[:maxRead])
			if nr > 0 {
				n += int64(nr)
				peakBytes += int64(nr)
			}
			if er != nil {
				return er
			}
		}
	}
	err = readFn()
	recordPeak()
	elapsed := time.Since(start)
	out.TotalMS = elapsed.Milliseconds()
	out.Bytes = n
	if elapsed > 0 {
		out.Mbps = (float64(n) * 8) / elapsed.Seconds() / 1e6
	}
	out.PeakMbps = peakMbps

	// Collect inflight RTT if goroutine completed
	select {
	case out.InflightRTT = <-inflightCh:
	default:
	}

	if err != nil && !errors.Is(err, io.EOF) {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			out.Error = "timeout"
		} else if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
			out.Error = "canceled"
		} else {
			out.Error = err.Error()
		}
		return out
	}

	out.OK = true
	return out
}
