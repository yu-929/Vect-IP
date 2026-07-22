package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yu-929/Vect-IP/internal/dns"
	"github.com/yu-929/Vect-IP/internal/engine"
	"github.com/yu-929/Vect-IP/internal/probe"
)

type ScanRequest struct {
	CIDRs                []string `json:"cidrs"`
	ASN                  int      `json:"asn"`
	Budget               int      `json:"budget"`
	Concurrency          int      `json:"concurrency"`
	Heads                int      `json:"heads"`
	Beam                 int      `json:"beam"`
	Timeout              string   `json:"timeout"`
	Host                 string   `json:"host"`
	Path                 string   `json:"path"`
	Rounds               int      `json:"rounds"`
	SkipFirst            int      `json:"skipFirst"`
	DownloadTop          int      `json:"downloadTop"`
	DownloadMode         string   `json:"downloadMode"`
	ColoAllow            string   `json:"coloAllow"`
	ColoExclude          string   `json:"coloExclude"`
	SplitStepV4          int      `json:"splitStepV4"`
	SplitStepV6          int      `json:"splitStepV6"`
	DiversityWeight      float64  `json:"diversityWeight"`
	SplitInterval        int      `json:"splitInterval"`
	MinSamplesSplit      int      `json:"minSamplesSplit"`
	MaxBitsV4            int      `json:"maxBitsV4"`
	MaxBitsV6            int      `json:"maxBitsV6"`
	Seed                 int64    `json:"seed"`
	IPVersion            int      `json:"ipVersion"`
	TopN                 int      `json:"topN"`
	DownloadBytes        int64    `json:"downloadBytes"`
	DownloadTimeout      int      `json:"downloadTimeout"`
	DownloadConcurrency  int      `json:"downloadConcurrency"`
	JitterFusionSearch   bool     `json:"jitterFusionSearch"`
	CustomDownloadURL    string   `json:"customDownloadUrl"`
	CustomDownloadEnabled bool    `json:"customDownloadEnabled"`
	SkipFailedRounds     bool     `json:"skipFailedRounds"`
	ColoDiversity        bool     `json:"coloDiversity"`
	SpeedFusion          bool     `json:"speedFusion"`
}

type ScanStatus struct {
	ID        string            `json:"id"`
	Status    string            `json:"status"`
	Progress  *ProgressData     `json:"progress,omitempty"`
	Result    []engine.TopResult `json:"result,omitempty"`
	Error     string            `json:"error,omitempty"`
}

type ProgressData struct {
	Completed     int     `json:"completed"`
	Budget        int     `json:"budget"`
	BestScore     float64 `json:"bestScore"`
	BestIP        string  `json:"bestIP"`
	BestPrefix    string  `json:"bestPrefix"`
	ElapsedMS     int64   `json:"elapsedMS"`
	Nodes         int     `json:"nodes"`
	Stage         int     `json:"stage"`
	DownloadIP    string  `json:"downloadIp,omitempty"`
	DownloadMbps  float64 `json:"downloadMbps,omitempty"`
	RetainedCount int     `json:"retainedCount,omitempty"`
}

type ScanSession struct {
	mu         sync.RWMutex
	status     string
	progress   ProgressData
	result     []engine.TopResult
	err        string
	cancel     context.CancelFunc
	subs       []chan ProgressData
	finishedAt time.Time
}

var (
	scans   = make(map[string]*ScanSession)
	scansMu sync.RWMutex
	nextID  int64
)

func newScanID() string {
	id := atomic.AddInt64(&nextID, 1)
	return fmt.Sprintf("%x", time.Now().UnixNano()) + fmt.Sprintf("%04x", id)
}

func init() {
	go sessionCleanupLoop()
}

func sessionCleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		scansMu.Lock()
		for id, s := range scans {
			s.mu.RLock()
			terminal := s.status == "completed" || s.status == "failed" || s.status == "cancelled"
			expired := !s.finishedAt.IsZero() && time.Since(s.finishedAt) > 5*time.Minute
			s.mu.RUnlock()
			if terminal && expired {
				delete(scans, id)
			}
		}
		scansMu.Unlock()
	}
}

func sendProgress(progress ProgressData, subs []chan ProgressData) {
	for _, ch := range subs {
		select {
		case ch <- progress:
		default:
		}
	}
}

func historyFilePath() string {
	dir := filepath.Join(os.TempDir(), "vect-history")
	os.MkdirAll(dir, 0755)
	return filepath.Join(dir, "full-history.json")
}

func loadHistoryFromFile() []interface{} {
	b, err := os.ReadFile(historyFilePath())
	if err != nil {
		return nil
	}
	var entries []interface{}
	if json.Unmarshal(b, &entries) == nil {
		return entries
	}
	return nil
}

func saveHistoryToFile(entries []interface{}) {
	b, err := json.Marshal(entries)
	if err != nil {
		log.Printf("history marshal error: %v", err)
		return
	}
	if err := os.WriteFile(historyFilePath(), b, 0644); err != nil {
		log.Printf("history write error: %v", err)
	}
}

func handleHistoryList(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		w.Header().Set("Content-Type", "application/json")
		entries := loadHistoryFromFile()
		if entries == nil {
			json.NewEncoder(w).Encode([]interface{}{})
		} else {
			json.NewEncoder(w).Encode(entries)
		}
	case "POST":
		var entries []interface{}
		if err := json.NewDecoder(r.Body).Decode(&entries); err != nil {
			http.Error(w, "invalid request", 400)
			return
		}
		saveHistoryToFile(entries)
		w.WriteHeader(200)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func SetupServer(port int, webFS fs.FS) *http.Server {

	mux := http.NewServeMux()
	mux.Handle("/", noCache(http.FileServer(http.FS(webFS))))
	mux.HandleFunc("/api/scan", handleScan)
	mux.HandleFunc("/api/scan/", handleScanByID)
	mux.HandleFunc("/api/resolve-asn/", handleResolveASN)
	mux.HandleFunc("/api/cancel/", handleCancel)
	mux.HandleFunc("/api/local-ip", handleLocalIP)
	mux.HandleFunc("/api/dns-upload", handleDNSUpload)
	mux.HandleFunc("/api/health", handleHealth)
	mux.HandleFunc("/api/colo-discover", handleColoDiscover)
	mux.HandleFunc("/api/resolve-url", handleResolveURL)
	mux.HandleFunc("/api/history/list", handleHistoryList)
	mux.HandleFunc("/api/github-upload", handleGitHubUpload)
	mux.HandleFunc("/api/resolve-domain", handleResolveDomain)
	mux.HandleFunc("/api/route-info", handleRouteInfo)

	server := &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", port),
		Handler: mux,
	}
	return server
}

func noCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		next.ServeHTTP(w, r)
	})
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request: "+err.Error(), 400)
		return
	}
	log.Printf("scan request: downloadTop=%d budget=%d cidrs=%d jitterFusionSearch=%v", req.DownloadTop, req.Budget, len(req.CIDRs), req.JitterFusionSearch)

	var cidrs []string
	cidrs = append(cidrs, req.CIDRs...)
	if req.ASN > 0 {
		asnCIDRs, err := resolveASN(req.ASN, req.IPVersion)
		if err != nil {
			http.Error(w, fmt.Sprintf("resolve ASN %d: %v", req.ASN, err), 400)
			return
		}
		cidrs = append(cidrs, asnCIDRs...)
	}
	if req.IPVersion > 0 {
		var filtered []string
		for _, c := range cidrs {
			prefix, err := netip.ParsePrefix(c)
			if err != nil {
				continue
			}
			if (req.IPVersion == 4 && prefix.Addr().Is4() || prefix.Addr().Is4In6()) ||
				(req.IPVersion == 6 && prefix.Addr().Is6() && !prefix.Addr().Is4In6()) {
				filtered = append(filtered, c)
			}
		}
		cidrs = filtered
	}
	if len(cidrs) == 0 {
		http.Error(w, "no CIDRs or ASN provided", 400)
		return
	}

	id := newScanID()
	session := &ScanSession{
		status: "running",
		progress: ProgressData{
			Budget: req.Budget,
		},
	}
	scansMu.Lock()
	scans[id] = session
	scansMu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	session.cancel = cancel

	timeout, _ := time.ParseDuration(req.Timeout)
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	topN := 20
	if req.TopN > 0 {
		topN = req.TopN
	}

	engineTopN := topN
	if req.SpeedFusion {
		engineTopN = topN * 3
	}

	cfg := engine.Config{
		Budget:          req.Budget,
		TopN:            engineTopN,
		Concurrency:     req.Concurrency,
		Heads:           req.Heads,
		Beam:            req.Beam,
		SplitStepV4:     req.SplitStepV4,
		SplitStepV6:     req.SplitStepV6,
		SplitInterval:   req.SplitInterval,
		MinSamplesSplit: req.MinSamplesSplit,
		MaxBitsV4:       req.MaxBitsV4,
		MaxBitsV6:       req.MaxBitsV6,
		Seed:            req.Seed,
		DiversityWeight: req.DiversityWeight,
		JitterFusionSearch: req.JitterFusionSearch,
		SkipFailedRounds:   req.SkipFailedRounds,
		ColoDiversity:      req.ColoDiversity,
		SpeedFusion:        req.SpeedFusion,
		OnProgress: func(info engine.ProgressInfo) {
			session.mu.Lock()
			session.progress = ProgressData{
				Completed:  info.Completed,
				Budget:     info.Budget,
				BestScore:  info.BestScore,
				BestIP:     info.BestIP,
				BestPrefix: info.BestPrefix,
				ElapsedMS:  info.Elapsed.Milliseconds(),
				Nodes:      info.Nodes,
				Stage:      3,
			}
			subs := make([]chan ProgressData, len(session.subs))
			copy(subs, session.subs)
			session.mu.Unlock()
			sendProgress(session.progress, subs)
		},
	}

	probeCfg := probe.Config{
		Timeout:          timeout,
		SNI:              req.Host,
		HostHeader:       req.Host,
		Path:             req.Path,
		Rounds:           req.Rounds,
		SkipFirst:        req.SkipFirst,
		SkipFailedRounds: req.SkipFailedRounds,
	}
	if req.Host == "" {
		probeCfg.SNI = "example.com"
		probeCfg.HostHeader = "example.com"
	}
	if req.Path == "" {
		probeCfg.Path = "/cdn-cgi/trace"
	}
	if req.SkipFirst <= 0 {
		probeCfg.SkipFirst = 1
	}

	engReq := engine.Request{
		CIDRs: cidrs,
		Probe: probeCfg,
	}

	if req.Concurrency <= 0 {
		cfg.Concurrency = 100
	}
	if req.Heads <= 0 {
		cfg.Heads = 4
	}
	if req.Budget <= 0 {
		cfg.Budget = 2000
	}
	if req.ColoAllow != "" {
		cfg.ColoAllow = strings.Split(req.ColoAllow, ",")
	}
	if req.ColoExclude != "" {
		cfg.ColoBlock = strings.Split(req.ColoExclude, ",")
	}

	go func() {
		session.mu.Lock()
		session.progress = ProgressData{Budget: req.Budget, Stage: 1, Completed: 1}
		subs := make([]chan ProgressData, len(session.subs))
		copy(subs, session.subs)
		session.mu.Unlock()
		sendProgress(session.progress, subs)

		session.mu.Lock()
		session.progress = ProgressData{Budget: req.Budget, Stage: 2, Completed: 1}
		subs = make([]chan ProgressData, len(session.subs))
		copy(subs, session.subs)
		session.mu.Unlock()
		sendProgress(session.progress, subs)

		eng := engine.New(cfg, probeCfg)
		resp, err := eng.Run(ctx, engReq)

		session.mu.Lock()
		if err != nil {
			session.finishedAt = time.Now()
			session.status = "failed"
			session.err = err.Error()
		} else {
			session.result = resp.Top
			log.Printf("handleScan: resp.Top count=%d", len(resp.Top))
		}
		// Filter out results with latency >= 6000ms
		filtered := make([]engine.TopResult, 0, len(session.result))
		for _, r := range session.result {
			if r.ScoreMS < 6000 {
				filtered = append(filtered, r)
			}
		}
		session.result = filtered
session.progress.Stage = 4
		session.progress.Completed = 1
		session.progress.RetainedCount = len(filtered)
		subs = make([]chan ProgressData, len(session.subs))
		copy(subs, session.subs)
		session.mu.Unlock()
		sendProgress(session.progress, subs)

		// Medium download stage: 1MB to filter out clearly slow candidates
		if req.SpeedFusion && len(session.result) > topN*2 {
			mediumCfg := probe.DownloadConfig{
				Timeout: 10 * time.Second,
				Bytes:   1_000_000,
			}
			mediumDlp := probe.NewDownloadProber(mediumCfg)
			mdlConc := req.DownloadConcurrency
			if mdlConc <= 1 {
				mdlConc = 5
			}
			sem := make(chan struct{}, mdlConc)
			var mWg sync.WaitGroup
			for i := range session.result {
				mWg.Add(1)
				sem <- struct{}{}
				go func(idx int) {
					defer mWg.Done()
					defer func() { <-sem }()
					dlCtx, dlCancel := context.WithTimeout(ctx, 10*time.Second)
					dr := mediumDlp.Download(dlCtx, session.result[idx].IP)
					dlCancel()
					session.result[idx].DownloadOK = dr.OK
					session.result[idx].DownloadBytes = dr.Bytes
					session.result[idx].DownloadMS = dr.TotalMS
					session.result[idx].DownloadMbps = dr.Mbps
					session.result[idx].DownloadPeakMbps = dr.PeakMbps
				}(i)
			}
			mWg.Wait()
			for i := range session.result {
				r := &session.result[i]
				score := float64(r.TotalMS)
				if r.DownloadOK && r.DownloadMbps > 0 {
					dlBonus := r.DownloadMbps * 0.5
					if dlBonus > score {
						dlBonus = score
					}
					score -= dlBonus
				}
				if req.JitterFusionSearch && r.JitterMS > 0 {
					score += r.JitterMS * 0.5
				}
				r.ScoreMS = score
			}
			sort.SliceStable(session.result, func(i, j int) bool {
				return session.result[i].ScoreMS < session.result[j].ScoreMS
			})
			keep := topN * 2
			if keep > len(session.result) {
				keep = len(session.result)
			}
			session.result = session.result[:keep]
		}

		// Run download tests if requested (keep SSE open during download)
		if req.DownloadTop > 0 && len(session.result) > 0 && session.result[0].ScoreMS < 6000 {
			session.mu.Lock()
			session.status = "downloading"
			session.mu.Unlock()

			dlTop := req.DownloadTop
			if req.SpeedFusion {
				dlTop = len(session.result)
			}
			if dlTop > len(session.result) {
				dlTop = len(session.result)
			}

dlBytes := req.DownloadBytes
			if dlBytes <= 0 {
				dlBytes = 1_000_000
			}
			dlTimeout := req.DownloadTimeout
			if dlTimeout <= 0 {
				dlTimeout = 3
			}
			dlCfg := probe.DownloadConfig{
				Timeout: time.Duration(dlTimeout) * time.Second,
				Bytes:   dlBytes,
			}
			if req.CustomDownloadEnabled && req.CustomDownloadURL != "" {
				if u, err := url.Parse(req.CustomDownloadURL); err == nil && u.Host != "" {
					dlCfg.CustomURL = true
					dlCfg.Path = u.Path
					if u.RawQuery != "" {
						dlCfg.Path += "?" + u.RawQuery
					}
					dlCfg.SNI = u.Hostname()
					dlCfg.HostName = u.Host
				}
			}

			dlp := probe.NewDownloadProber(dlCfg)
			dlConc := req.DownloadConcurrency
			if dlConc <= 1 {
				dlConc = 1
			}
			if dlConc > dlTop {
				dlConc = dlTop
			}

			var (
				mu           sync.Mutex
				successCount int
				inFlight     int
				wg           sync.WaitGroup
				workCh       = make(chan int, dlTop)
			)

			// Notify frontend immediately that download stage has started
			session.mu.Lock()
			session.progress.Stage = 5
			session.progress.Completed = 0
			session.progress.Budget = dlTop
			initP := session.progress
			dlSubs := make([]chan ProgressData, len(session.subs))
			copy(dlSubs, session.subs)
			session.mu.Unlock()
			sendProgress(initP, dlSubs)

			isSequential := req.DownloadMode == "sequential"

			// Start workers
			for w := 0; w < dlConc; w++ {
				wg.Add(1)
go func() {
					defer wg.Done()
					for idx := range workCh {
						mu.Lock()
						if successCount+inFlight >= dlTop {
							mu.Unlock()
							continue
						}
						inFlight++
						mu.Unlock()

						r := &session.result[idx]
						var dr probe.DownloadResult
						for attempt := 0; attempt < 3; attempt++ {
							dlCtx, dlCancel := context.WithTimeout(ctx, time.Duration(dlTimeout)*time.Second)
							dr = dlp.Download(dlCtx, r.IP)
							dlCancel()
							if dr.OK {
								break
							}
						}
						mu.Lock()
						r.DownloadOK = dr.OK
						r.DownloadBytes = dr.Bytes
						r.DownloadMS = dr.TotalMS
						r.DownloadMbps = dr.Mbps
						r.DownloadPeakMbps = dr.PeakMbps
						r.DownloadError = dr.Error
						if dr.OK {
							successCount++
						}
						inFlight--
						mu.Unlock()
						session.mu.Lock()
						session.progress.Stage = 5
						session.progress.Completed = successCount
						session.progress.Budget = dlTop
						session.progress.DownloadIP = r.IP.String()
						session.progress.DownloadMbps = dr.Mbps
						localProgress := session.progress
						dlSubs := make([]chan ProgressData, len(session.subs))
						copy(dlSubs, session.subs)
						session.mu.Unlock()
						sendProgress(localProgress, dlSubs)
					}
				}()
			}

			// Send work items
			if isSequential {
				for i := 0; i < len(session.result); i++ {
					workCh <- i
				}
			} else {
				for i := 0; i < dlTop; i++ {
					workCh <- i
				}
			}
			close(workCh)
			wg.Wait()

			// Stability verification: repeat download on top 5, take minimum speed
			if req.SpeedFusion {
				verifyCount := 5
				if verifyCount > len(session.result) {
					verifyCount = len(session.result)
				}
				for i := 0; i < verifyCount; i++ {
					r := &session.result[i]
					if !r.DownloadOK {
						continue
					}
					minMbps := r.DownloadMbps
					for attempt := 0; attempt < 2; attempt++ {
						dlCtx, dlCancel := context.WithTimeout(ctx, time.Duration(dlTimeout)*time.Second)
						dr := dlp.Download(dlCtx, r.IP)
						dlCancel()
						if dr.OK && dr.Mbps < minMbps {
							minMbps = dr.Mbps
						}
					}
					r.DownloadMbps = minMbps
				}
			}
		}

		// Re-sort by comprehensive score: latency + bandwidth + download speed
		session.mu.Lock()
		if req.SpeedFusion {
			for i := range session.result {
				r := &session.result[i]
				score := float64(r.TotalMS)
				if r.DownloadOK && r.DownloadMbps > 0 {
					dlBonus := r.DownloadMbps * 0.5
					if dlBonus > score {
						dlBonus = score
					}
					score -= dlBonus
				}
				if req.JitterFusionSearch && r.JitterMS > 0 {
					score += r.JitterMS * 0.5
				}
				r.ScoreMS = score
			}
		}
		sort.SliceStable(session.result, func(i, j int) bool {
			return session.result[i].ScoreMS < session.result[j].ScoreMS
		})
		if req.SpeedFusion && len(session.result) > topN {
			session.result = session.result[:topN]
		}
		session.finishedAt = time.Now()
		if session.status != "failed" {
			session.status = "completed"
		}
		session.mu.Unlock()

		// Close SSE channels after all processing is done
		session.mu.Lock()
		allSubs := session.subs
		session.subs = nil
		session.mu.Unlock()
		for _, ch := range allSubs {
			close(ch)
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"id": id})
}

func handleScanByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/scan/")
	if id == "" {
		http.Error(w, "missing scan id", 400)
		return
	}
	if r.URL.RawQuery == "subscribe" {
		handleProgressSSE(w, r, id)
		return
	}

	scansMu.RLock()
	session, ok := scans[id]
	scansMu.RUnlock()
	if !ok {
		http.Error(w, "scan not found", 404)
		return
	}

	session.mu.RLock()
	prog := session.progress
	status := ScanStatus{
		ID:       id,
		Status:   session.status,
		Progress: &prog,
		Error:    session.err,
	}
	if session.status == "completed" {
		status.Result = append([]engine.TopResult(nil), session.result...)
	}
	session.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func handleProgressSSE(w http.ResponseWriter, r *http.Request, id string) {
	scansMu.RLock()
	session, ok := scans[id]
	scansMu.RUnlock()
	if !ok {
		http.Error(w, "scan not found", 404)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", 500)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan ProgressData, 8)
	session.mu.Lock()
	if session.status == "completed" || session.status == "failed" {
		session.mu.Unlock()
		fmt.Fprintf(w, "event: done\ndata: \n\n")
		flusher.Flush()
		return
	}
	session.subs = append(session.subs, ch)
	ch <- session.progress
	session.mu.Unlock()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case data, ok := <-ch:
			if !ok {
				fmt.Fprintf(w, "event: done\ndata: \n\n")
				flusher.Flush()
				return
			}
			b, _ := json.Marshal(data)
			fmt.Fprintf(w, "data: %s\n\n", b)
			flusher.Flush()
		}
	}
}

func handleCancel(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/cancel/")
	if id == "" {
		http.Error(w, "missing scan id", 400)
		return
	}

	scansMu.RLock()
	session, ok := scans[id]
	scansMu.RUnlock()
	if !ok {
		http.Error(w, "scan not found", 404)
		return
	}

	session.mu.Lock()
	if session.status == "running" {
		session.cancel()
		session.finishedAt = time.Now()
		session.status = "cancelled"
	}
	session.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "cancelled"})
}

func handleResolveASN(w http.ResponseWriter, r *http.Request) {
	asnStr := strings.TrimPrefix(r.URL.Path, "/api/resolve-asn/")
	asn, err := strconv.Atoi(asnStr)
	if err != nil {
		http.Error(w, "invalid ASN", 400)
		return
	}

	ipVer, _ := strconv.Atoi(r.URL.Query().Get("version"))

	cidrs, err := resolveASN(asn, ipVer)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"asn":   asn,
		"cidrs": cidrs,
	})
}

func handleRouteInfo(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, "missing ip parameter", 400)
		return
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://ip-api.com/json/" + ip + "?fields=as,asname")
	if err != nil {
		http.Error(w, "lookup failed", 500)
		return
	}
	defer resp.Body.Close()
	var data struct {
		AS     string `json:"as"`
		ASName string `json:"asname"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		http.Error(w, "parse failed", 500)
		return
	}
	asn := 0
	if n, err := fmt.Sscanf(data.AS, "AS%d", &asn); err != nil || n != 1 {
		asn = 0
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"asn":     asn,
		"asname":  data.ASName,
	})
}

func resolveASN(asn int, ipVersion int) ([]string, error) {
	url := fmt.Sprintf("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS%d", asn)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("RIPE API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("RIPE API status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result struct {
		Data struct {
			Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"prefixes"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse RIPE response: %w", err)
	}

	var cidrs []string
	var seen = make(map[string]bool)
	for _, p := range result.Data.Prefixes {
		if !seen[p.Prefix] {
			if ipVersion > 0 {
				prefix, err := netip.ParsePrefix(p.Prefix)
				if err != nil {
					continue
				}
				is4 := prefix.Addr().Is4() || prefix.Addr().Is4In6()
				if (ipVersion == 4 && !is4) || (ipVersion == 6 && is4) {
					continue
				}
			}
			cidrs = append(cidrs, p.Prefix)
			seen[p.Prefix] = true
		}
	}

	if len(cidrs) == 0 {
		return nil, fmt.Errorf("no prefixes found for AS%d", asn)
	}

	sort.Strings(cidrs)
	return cidrs, nil
}

type LocalIPInfo struct {
	PublicIP  string   `json:"publicIP"`
	LocalIPs  []string `json:"localIPs"`
	Hostname  string   `json:"hostname"`
	ISP       string   `json:"isp,omitempty"`
	Location  string   `json:"location,omitempty"`
}

func handleLocalIP(w http.ResponseWriter, r *http.Request) {
	info := LocalIPInfo{}

	host, _ := os.Hostname()
	info.Hostname = host

	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipnet.IP.IsLoopback() || ipnet.IP.IsLinkLocalUnicast() {
				continue
			}
			info.LocalIPs = append(info.LocalIPs, ipnet.IP.String())
		}
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://ip-api.com/json/?lang=zh-CN")
	if err == nil {
		defer resp.Body.Close()
		var ipData struct {
			Query    string `json:"query"`
			ISP      string `json:"isp"`
			Org      string `json:"org"`
			City     string `json:"city"`
			Country  string `json:"country"`
			Region   string `json:"regionName"`
		}
		if json.NewDecoder(resp.Body).Decode(&ipData) == nil {
			info.PublicIP = ipData.Query
			info.ISP = translateISP(ipData.ISP)
			if ipData.Org != "" && ipData.Org != ipData.ISP {
				info.ISP = translateISP(ipData.Org)
			}
			info.Location = translateLocation(ipData.City + " | " + ipData.Region + " | " + ipData.Country)
		}
	}
	if info.PublicIP == "" {
		resp, err := client.Get("https://api.ipify.org?format=json")
		if err == nil {
			defer resp.Body.Close()
			var ipData struct {
				IP string `json:"ip"`
			}
			if json.NewDecoder(resp.Body).Decode(&ipData) == nil {
				info.PublicIP = ipData.IP
			}
		}
	}
	if info.PublicIP == "" {
		info.PublicIP = "unknown"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

func translateISP(isp string) string {
	m := map[string]string{
		"Alibaba.com Singapore E-Commerce Private Limited": "阿里云新加坡",
		"Alibaba Cloud":                     "阿里云",
		"Alibaba":                            "阿里巴巴",
		"Cloudflare Inc":                     "Cloudflare",
		"Cloudflare, Inc.":                   "Cloudflare",
		"Amazon.com, Inc.":                   "亚马逊云(AWS)",
		"Amazon Data Services":               "亚马逊云(AWS)",
		"Amazon":                             "亚马逊云(AWS)",
		"Google LLC":                         "谷歌云(GCP)",
		"Google Cloud":                       "谷歌云(GCP)",
		"Microsoft Corporation":              "微软云(Azure)",
		"Microsoft Azure":                    "微软云(Azure)",
		"DigitalOcean, LLC":                  "DigitalOcean",
		"Linode, LLC":                        "Linode",
		"Vultr Holdings LLC":                 "Vultr",
		"Tencent Cloud Computing":            "腾讯云",
		"Huawei Cloud":                       "华为云",
		"China Telecom":                      "中国电信",
		"China Unicom":                       "中国联通",
		"China Mobile":                       "中国移动",
		"Hong Kong Broadband Network":        "香港宽频",
		"HKT Limited":                        "香港电讯",
		"PCCW":                               "电讯盈科",
		"Netvigator":                         "网上行",
		"Hetzner Online GmbH":                "Hetzner",
		"Hetzner Online":                     "Hetzner",
		"OVH SAS":                            "OVH",
		"OVH Sp. z o.o.":                     "OVH",
		"Oracle Corporation":                 "甲骨文云(Oracle)",
		"Oracle Cloud":                       "甲骨文云(Oracle)",
		"Akamai Technologies":                "Akamai",
		"Akamai International B.V.":          "Akamai",
		"Fastly, Inc.":                       "Fastly",
		"Cogent Communications":              "Cogent",
		"Cogent Communications, Inc.":        "Cogent",
		"NTT Communications":                 "NTT",
		"NTT America":                        "NTT",
		"GTT Communications":                 "GTT",
		"GTT Communications Inc.":            "GTT",
		"Comcast Cable":                      "Comcast",
		"Comcast IP Services":                "Comcast",
		"AT&T Services":                      "AT&T",
		"AT&T Corp.":                         "AT&T",
		"Verizon Business":                   "Verizon",
		"Verizon Communications":             "Verizon",
		"Deutsche Telekom AG":                "德国电信",
		"Vodafone GmbH":                      "沃达丰",
		"Vodafone Group":                     "沃达丰",
		"Orange S.A.":                        "Orange",
		"Orange SA":                          "Orange",
		"Telefonica":                         "西班牙电信",
		"Telefonica de Espana":               "西班牙电信",
		"British Telecom":                    "英国电信",
		"BT Communications":                  "英国电信",
		"Singtel":                            "新加坡电信",
		"Singapore Telecom":                  "新加坡电信",
		"KDDI Corporation":                   "KDDI",
		"KDDI America":                       "KDDI",
		"SoftBank Corp.":                     "软银(SoftBank)",
		"SoftBank Mobile":                    "软银(SoftBank)",
		"IIJ":                                "IIJ",
		"Internet Initiative Japan":          "IIJ",
		"M247 Ltd":                           "M247",
		"M247 Europe SRL":                    "M247",
		"Choopa, LLC":                        "Choopa",
		"Contabo GmbH":                       "Contabo",
		"Scaleway S.A.S.":                    "Scaleway",
		"UpCloud Ltd":                        "UpCloud",
		"Rackspace Hosting":                  "Rackspace",
		"Rackspace US":                       "Rackspace",
		"IBM Cloud":                          "IBM 云",
		"IBM Corporation":                    "IBM 云",
		"Yandex Cloud":                       "Yandex",
		"Yandex LLC":                         "Yandex",
	}
	if v, ok := m[isp]; ok {
		return v
	}
	prefix := map[string]string{
		"CNC Group":          "中国网通",
		"Chinanet":           "中国电信",
		"China169":           "中国联通",
		"CMNET":              "中国移动",
		"CNCN":               "中国网通",
		"BGP.CN":             "中国BGP",
		"Hetzner":            "Hetzner",
		"Oracle":             "甲骨文云(Oracle)",
		"OVH":                "OVH",
		"Akamai":             "Akamai",
		"Fastly":             "Fastly",
		"Cogent":             "Cogent",
		"NTT":                "NTT",
		"Comcast":            "Comcast",
		"AT&T":               "AT&T",
		"Verizon":            "Verizon",
		"SoftBank":           "软银(SoftBank)",
		"Singtel":            "新加坡电信",
		"KDDI":               "KDDI",
	}
	for k, v := range prefix {
		if strings.HasPrefix(isp, k) {
			return v
		}
	}
	return isp
}

func translateLocation(loc string) string {
	m := map[string]string{
		"Kowloon":     "九龙",
		"Hong Kong":   "香港",
		"Macau":       "澳门",
		"Taipei":      "台北",
		"Tokyo":       "东京",
		"Seoul":       "首尔",
		"Singapore":   "新加坡",
		"Bangkok":     "曼谷",
		"London":      "伦敦",
		"Frankfurt":   "法兰克福",
		"Amsterdam":   "阿姆斯特丹",
		"Paris":       "巴黎",
		"Dublin":      "都柏林",
		"Milan":       "米兰",
		"Zurich":      "苏黎世",
		"Stockholm":   "斯德哥尔摩",
		"Moscow":      "莫斯科",
		"Sydney":      "悉尼",
		"Melbourne":   "墨尔本",
		"Silicon Valley": "硅谷",
		"San Jose":    "圣何塞",
		"Los Angeles": "洛杉矶",
		"Dallas":      "达拉斯",
		"Chicago":     "芝加哥",
		"New York":    "纽约",
		"Ashburn":     "阿什本",
		"Miami":       "迈阿密",
		"Toronto":     "多伦多",
		"Vancouver":   "温哥华",
		"Montreal":    "蒙特利尔",
	}
	for en, zh := range m {
		loc = strings.ReplaceAll(loc, en, zh)
	}
	return loc
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleColoDiscover(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		CIDRs []string `json:"cidrs"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	if len(req.CIDRs) == 0 {
		http.Error(w, "no CIDRs", 400)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg := engine.Config{
		Budget:      100,
		TopN:        100,
		Concurrency: 100,
		Heads:       4,
		Beam:        32,
		OnProgress:  func(info engine.ProgressInfo) {},
	}
	probeCfg := probe.Config{
		Timeout:    3 * time.Second,
		SNI:        "example.com",
		HostHeader: "example.com",
		Path:       "/cdn-cgi/trace",
		Rounds:     1,
	}
	engReq := engine.Request{
		CIDRs: req.CIDRs,
		Probe: probeCfg,
	}

	eng := engine.New(cfg, probeCfg)
	resp, err := eng.Run(ctx, engReq)
	if err != nil {
		http.Error(w, "scan failed: "+err.Error(), 500)
		return
	}

	coloCount := make(map[string]int)
	for _, r := range resp.Top {
		if r.Trace != nil {
			if c, ok := r.Trace["colo"]; ok && c != "" {
				coloCount[c]++
			}
		}
	}

	type coloEntry struct {
		Colo  string `json:"colo"`
		Count int    `json:"count"`
	}
	var entries []coloEntry
	for c, n := range coloCount {
		entries = append(entries, coloEntry{c, n})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Count > entries[j].Count })

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

func handleDNSUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Provider       string   `json:"provider"`
		Token          string   `json:"token"`
		Zone           string   `json:"zone"`
		Subdomain      string   `json:"subdomain"`
		Count          int      `json:"count"`
		IPs            []string `json:"ips"`
		FilterIPv6Only bool     `json:"filter_ipv6_only"`
		RecordType     string   `json:"record_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	if req.Provider == "" || req.Token == "" || req.Zone == "" || req.Subdomain == "" {
		http.Error(w, "provider, token, zone, subdomain required", 400)
		return
	}
	if len(req.IPs) == 0 {
		http.Error(w, "no IPs provided", 400)
		return
	}

	ips := make([]netip.Addr, 0, len(req.IPs))
	for _, s := range req.IPs {
		ip, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		ips = append(ips, ip)
	}
	if len(ips) == 0 {
		http.Error(w, "no valid IPs parsed", 400)
		return
	}

	if req.FilterIPv6Only {
		ips = dns.FilterIPv6OnlyByAPI(ips)
		if len(ips) == 0 {
			http.Error(w, "no IPv4/dual-stack IPs after filtering", 400)
			return
		}
	}

	count := req.Count
	if count <= 0 || count > len(ips) {
		count = len(ips)
	}

	cfg := dns.Config{
		Provider:    req.Provider,
		Token:       req.Token,
		Zone:        req.Zone,
		Subdomain:   req.Subdomain,
		UploadCount: count,
		RecordType:  req.RecordType,
	}
	provider, err := dns.NewProvider(cfg)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	if err := dns.Upload(ctx, provider, req.Subdomain, ips[:count], false); err != nil {
		http.Error(w, "upload failed: "+err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":    true,
		"count": count,
	})
}

type resolveURLReq struct {
	URL string `json:"url"`
}

func handleResolveURL(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req resolveURLReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request: "+err.Error(), 400)
		return
	}
	if req.URL == "" {
		http.Error(w, "url is required", 400)
		return
	}

	var fetchURL string
	if strings.HasPrefix(req.URL, "sub://") {
		fetchURL = "https://" + req.URL[6:]
	} else {
		u, err := url.Parse(req.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			http.Error(w, "invalid url", 400)
			return
		}
		fetchURL = req.URL
	}

	client := &http.Client{Timeout: 30 * time.Second}
	req2, _ := http.NewRequest("GET", fetchURL, nil)
	req2.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15")
	resp, err := client.Do(req2)
	if err != nil {
http.Error(w, "fetch failed: "+err.Error(), http.StatusBadGateway)

		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "read failed: "+err.Error(), http.StatusBadGateway)
		return
	}

	content := string(body)
	// Try base64 decode for sub content
	if strings.HasPrefix(req.URL, "sub://") {
		if decoded, err := base64.StdEncoding.DecodeString(content); err == nil {
			content = string(decoded)
		} else if decoded, err := base64.RawStdEncoding.DecodeString(content); err == nil {
			content = string(decoded)
		}
	}

	ipRe := regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)
	var cidrs []string
	seen := map[string]bool{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		ip := extractIPFromProxyURI(line)
		if ip == "" {
			if m := ipRe.FindStringSubmatch(line); m != nil {
				ip = m[1]
			}
		}
		if ip == "" || net.ParseIP(ip) == nil {
			continue
		}
		idx := strings.Index(line, ip)
		if idx < 0 {
			idx = 0
		}
		rest := strings.TrimSpace(line[idx+len(ip):])
		cidr := ip + "/24"
		parts := strings.Fields(rest)
		for _, p := range parts {
			if strings.Contains(p, "/") {
				var pp netip.Prefix
				if err := pp.UnmarshalText([]byte(p)); err == nil && pp.IsValid() {
					cidr = p
					break
				}
			}
		}
		if !seen[cidr] {
			cidrs = append(cidrs, cidr)
			seen[cidr] = true
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"cidrs": cidrs,
		"count": len(cidrs),
	})
}

func extractIPFromProxyURI(uri string) string {
	// vmess://base64 -> decode JSON, extract "add" or "host"
	if strings.HasPrefix(uri, "vmess://") {
		if b, err := base64.StdEncoding.DecodeString(uri[8:]); err == nil {
			var v struct {
				Add  string `json:"add"`
				Host string `json:"host"`
			}
			if json.Unmarshal(b, &v) == nil {
				if net.ParseIP(v.Add) != nil {
					return v.Add
				}
				if net.ParseIP(v.Host) != nil {
					return v.Host
				}
			}
		} else if b, err := base64.RawStdEncoding.DecodeString(uri[8:]); err == nil {
			var v struct {
				Add  string `json:"add"`
				Host string `json:"host"`
			}
			if json.Unmarshal(b, &v) == nil {
				if net.ParseIP(v.Add) != nil {
					return v.Add
				}
				if net.ParseIP(v.Host) != nil {
					return v.Host
				}
			}
		}
		return ""
	}

	// ss://base64 -> decode as "method:password@host:port"
	if strings.HasPrefix(uri, "ss://") {
		raw := uri[5:]
		if idx := strings.IndexByte(raw, '#'); idx >= 0 {
			raw = raw[:idx]
		}
		if b, err := base64.StdEncoding.DecodeString(raw); err == nil {
			if h, _, err := net.SplitHostPort(string(b)); err == nil && net.ParseIP(h) != nil {
				return h
			}
		} else if b, err := base64.RawStdEncoding.DecodeString(raw); err == nil {
			if h, _, err := net.SplitHostPort(string(b)); err == nil && net.ParseIP(h) != nil {
				return h
			}
		}
		// Also try as SIP002 format: ss://base64@host:port
		if idx := strings.Index(raw, "@"); idx >= 0 {
			if h, _, err := net.SplitHostPort(raw[idx+1:]); err == nil && net.ParseIP(h) != nil {
				return h
			}
		}
		return ""
	}

	// ssr://base64 -> decode as "server:port:protocol:method:obfs:password"
	if strings.HasPrefix(uri, "ssr://") {
		raw := uri[6:]
		if b, err := base64.StdEncoding.DecodeString(raw); err == nil {
			parts := strings.SplitN(string(b), ":", 2)
			if len(parts) >= 1 && net.ParseIP(parts[0]) != nil {
				return parts[0]
			}
		} else if b, err := base64.RawStdEncoding.DecodeString(raw); err == nil {
			parts := strings.SplitN(string(b), ":", 2)
			if len(parts) >= 1 && net.ParseIP(parts[0]) != nil {
				return parts[0]
			}
		}
		return ""
	}

	// trojan://, vless://, hysteria2://, hysteria://, tuic://, socks5://
	// All have format: scheme://[userinfo@]host:port
	if strings.HasPrefix(uri, "trojan://") || strings.HasPrefix(uri, "vless://") ||
		strings.HasPrefix(uri, "hysteria2://") || strings.HasPrefix(uri, "hysteria://") ||
		strings.HasPrefix(uri, "tuic://") || strings.HasPrefix(uri, "socks5://") {
		u, err := url.Parse(uri)
		if err != nil {
			return ""
		}
		if net.ParseIP(u.Hostname()) != nil {
			return u.Hostname()
		}
		// Some formats have ip in the userinfo part for trojan
		if u.User != nil && net.ParseIP(u.User.String()) != nil {
			return u.User.String()
		}
		return ""
	}

	return ""
}

func handleResolveDomain(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "domain required", 400)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", domain)
	if err != nil {
		http.Error(w, "dns lookup failed: "+err.Error(), http.StatusBadGateway)
		return
	}

	seen := map[string]bool{}
	var cidrs []string
	for _, ip := range ips {
		s := ip.String()
		if ip.Is4() {
			parts := strings.Split(s, ".")
			if len(parts) == 4 {
				s = parts[0] + "." + parts[1] + "." + parts[2] + ".0/24"
			}
		}
		if !seen[s] {
			cidrs = append(cidrs, s)
			seen[s] = true
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"cidrs": cidrs,
		"count": len(cidrs),
	})
}

func handleGitHubUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Token    string   `json:"token"`
		Repo     string   `json:"repo"`
		Path     string   `json:"path"`
		Branch   string   `json:"branch"`
		Message  string   `json:"message"`
		Ips      []string `json:"ips"`
		Filename string   `json:"filename"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	if req.Token == "" || req.Repo == "" || len(req.Ips) == 0 {
		http.Error(w, "token, repo, ips required", 400)
		return
	}
	if req.Branch == "" {
		req.Branch = "main"
	}
	req.Repo = strings.TrimSpace(strings.TrimRight(req.Repo, "/"))
	if strings.Count(req.Repo, "/") != 1 {
		http.Error(w, "invalid repo format, expected owner/repo", 400)
		return
	}
	content := strings.Join(req.Ips, "\n") + "\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(content))

	filePath := req.Path
	if filePath == "" {
		filePath = "ips.txt"
	}
	if req.Filename != "" {
		filePath = req.Filename
	}
	filePath = strings.TrimLeft(filePath, "/")
	if filePath == "" {
		filePath = "ips.txt"
	}
	parts := strings.Split(filePath, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	encodedPath := strings.Join(parts, "/")

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/contents/%s", req.Repo, encodedPath)

	getReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	getReq.Header.Set("Authorization", "Bearer "+req.Token)
	getReq.Header.Set("Accept", "application/vnd.github.v3+json")
	getReq.Header.Set("User-Agent", "Vect-IP/1.31")

	getResp, err := http.DefaultClient.Do(getReq)
	var sha string
	if err == nil && getResp.StatusCode == 200 {
		var existing struct {
			SHA string `json:"sha"`
		}
		json.NewDecoder(getResp.Body).Decode(&existing)
		sha = existing.SHA
	} else if err != nil && getResp == nil {
		// GET failed, will try PUT anyway
	}
	if getResp != nil {
		getResp.Body.Close()
	}

	msg := req.Message
	if msg == "" {
		now := time.Now().In(time.FixedZone("CST", 8*3600))
		msg = fmt.Sprintf("New IP list (%d items) Time: %s", len(req.Ips), now.Format("15:04 on January 2, 2006"))
	}

	payload := map[string]interface{}{
		"message": msg,
		"content": encoded,
		"branch":  req.Branch,
	}
	if sha != "" {
		payload["sha"] = sha
	}

	body, _ := json.Marshal(payload)
	putReq, _ := http.NewRequestWithContext(ctx, http.MethodPut, apiURL, bytes.NewReader(body))
	putReq.Header.Set("Authorization", "Bearer "+req.Token)
	putReq.Header.Set("Content-Type", "application/json")
	putReq.Header.Set("Accept", "application/vnd.github.v3+json")
	putReq.Header.Set("User-Agent", "Vect-IP/1.31")

	putResp, err := http.DefaultClient.Do(putReq)
	if err != nil {
		http.Error(w, "github api error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer putResp.Body.Close()

	respBody, _ := io.ReadAll(putResp.Body)
	if putResp.StatusCode > 299 {
		http.Error(w, "github api error: "+string(respBody), putResp.StatusCode)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":    true,
		"count": len(req.Ips),
	})
}