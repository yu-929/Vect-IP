package probe

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

// Downloader is the common interface for single and multi-stream downloaders.
type Downloader interface {
	Download(ctx context.Context, ip netip.Addr) DownloadResult
}

type MultiStreamDownloadProber struct {
	cfg     DownloadConfig
	streams int
}

func NewMultiStreamDownloadProber(cfg DownloadConfig, streams int) *MultiStreamDownloadProber {
	if streams < 2 {
		streams = 2
	}
	return &MultiStreamDownloadProber{cfg: cfg, streams: streams}
}

func (p *MultiStreamDownloadProber) Download(ctx context.Context, ip netip.Addr) DownloadResult {
	start := time.Now()
	out := DownloadResult{
		IP:      ip,
		When:    start,
		Streams: p.streams,
		OK:      true,
	}

	streamCfg := p.cfg
	if !streamCfg.CustomURL {
		streamCfg.Bytes = streamCfg.Bytes / int64(p.streams)
		if streamCfg.Bytes < 1 {
			streamCfg.Bytes = 1
		}
	}

	var (
		mu          sync.Mutex
		totalBytes  int64
		peakMbps    float64
		maxMS       int64
		baselineRTT float64
		inflightRTT float64
		anyOK       bool
		wg          sync.WaitGroup
	)

	for s := 0; s < p.streams; s++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			prober := NewDownloadProber(streamCfg)
			dr := prober.Download(ctx, ip)
			mu.Lock()
			if dr.OK {
				anyOK = true
				totalBytes += dr.Bytes
				if dr.Mbps > peakMbps {
					peakMbps = dr.Mbps
				}
				if dr.TotalMS > maxMS {
					maxMS = dr.TotalMS
				}
				if dr.BaselineRTT > baselineRTT {
					baselineRTT = dr.BaselineRTT
				}
				if dr.InflightRTT > inflightRTT {
					inflightRTT = dr.InflightRTT
				}
			} else if !anyOK {
				out.Error = dr.Error
				out.Status = dr.Status
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	if !anyOK {
		out.TotalMS = time.Since(start).Milliseconds()
		return out
	}

	elapsed := time.Since(start)
	out.TotalMS = elapsed.Milliseconds()
	out.Bytes = totalBytes
	out.BaselineRTT = baselineRTT
	out.InflightRTT = inflightRTT
	if maxMS > out.TotalMS {
		out.TotalMS = maxMS
	}
	if elapsed > 0 {
		out.Mbps = (float64(totalBytes) * 8) / elapsed.Seconds() / 1e6
	}
	out.PeakMbps = peakMbps
	out.OK = true
	return out
}