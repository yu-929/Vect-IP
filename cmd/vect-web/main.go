package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
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
	"github.com/yu-929/Vect-IP/web"
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
	CustomDownloadUrl    string   `json:"customDownloadUrl"`
	CustomDownloadEnabled bool    `json:"customDownloadEnabled"`
	DownloadBytes        int64    `json:"downloadBytes"`
	DownloadTimeout      int      `json:"downloadTimeout"`
	DownloadConcurrency  int      `json:"downloadConcurrency"`
	JitterFusionSearch   bool     `json:"jitterFusionSearch"`
	SkipFailedRounds     bool     `json:"skipFailedRounds"`
	ColoDiversity        bool     `json:"coloDiversity"`
}

type ScanStatus struct {
	ID        string          `json:"id"`
	Status    string          `json:"status"`
	Progress  *ProgressData   `json:"progress,omitempty"`
	Result    []engine.TopResult `json:"result,omitempty"`
	Error     string          `json:"error,omitempty"`
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

type CfnbSession struct {
	mu         sync.RWMutex
	status     string
	progress   ProgressData
	result     []map[string]interface{}
	output     string
	err        string
	cancel     context.CancelFunc
	subs       []chan ProgressData
	finishedAt time.Time
}

var (
	scans     = make(map[string]*ScanSession)
	scansMu   sync.RWMutex
	nextID    int64
	historyMu sync.Mutex
	cfnbScans   = make(map[string]*CfnbSession)
	cfnbScansMu sync.RWMutex
	cfnbIDCounter int64
	cfnbServerPort string
)

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

		// Cleanup old cfnb sessions
		cfnbScansMu.Lock()
		for id, s := range cfnbScans {
			s.mu.Lock()
			if s.status == "completed" || s.status == "failed" {
				if time.Since(s.finishedAt) > 10*time.Minute {
					delete(cfnbScans, id)
				}
			}
			s.mu.Unlock()
		}
		cfnbScansMu.Unlock()
	}
}

func historyDir() string {
	dir := filepath.Join(os.TempDir(), "vect-history")
	os.MkdirAll(dir, 0755)
	return dir
}

func loadHistory() []map[string]interface{} {
	historyMu.Lock()
	defer historyMu.Unlock()
	entries, _ := filepath.Glob(filepath.Join(historyDir(), "*.json"))
	sort.Slice(entries, func(i, j int) bool { return entries[i] > entries[j] })
	var result []map[string]interface{} = []map[string]interface{}{}
	for _, e := range entries {
		b, err := os.ReadFile(e)
		if err != nil {
			continue
		}
		var entry map[string]interface{}
		if json.Unmarshal(b, &entry) == nil {
			result = append(result, entry)
		}
		if len(result) >= 50 {
			break
		}
	}
	return result
}

func saveHistory(entry map[string]interface{}) string {
	historyMu.Lock()
	defer historyMu.Unlock()
	id := fmt.Sprintf("%x", time.Now().UnixNano())
	entry["_id"] = id
	b, _ := json.Marshal(entry)
	os.WriteFile(filepath.Join(historyDir(), id+".json"), b, 0644)
	// Keep max 50 files
	files, _ := filepath.Glob(filepath.Join(historyDir(), "*.json"))
	sort.Slice(files, func(i, j int) bool { return files[i] > files[j] })
	for i := 50; i < len(files); i++ {
		os.Remove(files[i])
	}
	return id
}

func deleteHistory(id string) {
	historyMu.Lock()
	defer historyMu.Unlock()
	os.Remove(filepath.Join(historyDir(), id+".json"))
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

func handleHistory(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(loadHistory())
	case "POST":
		var entry map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
			http.Error(w, "invalid request", 400)
			return
		}
		id := saveHistory(entry)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"id": id})
	case "DELETE":
		id := strings.TrimPrefix(r.URL.Path, "/api/history/")
		if id == "" {
			http.Error(w, "missing id", 400)
			return
		}
		deleteHistory(id)
		w.WriteHeader(204)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleDNSUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ScanID         string   `json:"scanId"`
		Provider       string   `json:"provider"`
		Token          string   `json:"token"`
		Zone           string   `json:"zone"`
		Subdomain      string   `json:"subdomain"`
		Count          int      `json:"count"`
		TeamID         string   `json:"teamId"`
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

	var dlOK []netip.Addr
	if len(req.IPs) > 0 {
		for _, s := range req.IPs {
			ip, err := netip.ParseAddr(s)
			if err != nil {
				continue
			}
			dlOK = append(dlOK, ip)
		}
	} else {
		scansMu.RLock()
		session, ok := scans[req.ScanID]
		scansMu.RUnlock()
		if !ok {
			http.Error(w, "scan not found", 404)
			return
		}
		session.mu.RLock()
		results := session.result
		session.mu.RUnlock()
		for _, r := range results {
			if r.DownloadOK {
				dlOK = append(dlOK, r.IP)
			}
		}
	}
	if len(dlOK) == 0 {
		http.Error(w, "no IPs available", 400)
		return
	}

	if req.FilterIPv6Only {
		dlOK = dns.FilterIPv6OnlyByAPI(dlOK)
		if len(dlOK) == 0 {
			http.Error(w, "no IPv4/dual-stack IPs after filtering", 400)
			return
		}
	}

	count := req.Count
	if count <= 0 || count > len(dlOK) {
		count = len(dlOK)
	}

	cfg := dns.Config{
		Provider:    req.Provider,
		Token:       req.Token,
		Zone:        req.Zone,
		Subdomain:   req.Subdomain,
		UploadCount: count,
		TeamID:      req.TeamID,
		RecordType:  req.RecordType,
	}
	provider, err := dns.NewProvider(cfg)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	ips := dlOK[:count]
	if err := dns.Upload(ctx, provider, req.Subdomain, ips, false); err != nil {
		http.Error(w, "upload failed: "+err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":    true,
		"count": len(ips),
	})
}

func noCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		next.ServeHTTP(w, r)
	})
}

func main() {
	port := "8080"
	if p := os.Getenv("PORT"); p != "" {
		port = p
	}
	cfnbServerPort = port

	go sessionCleanupLoop()

	http.Handle("/", noCache(http.FileServer(http.FS(web.FS))))

	http.HandleFunc("/api/scan", handleScan)
	http.HandleFunc("/api/scan/", handleScanByID)
	http.HandleFunc("/api/resolve-asn/", handleResolveASN)
	http.HandleFunc("/api/cancel/", handleCancel)
	http.HandleFunc("/api/local-ip", handleLocalIP)
	http.HandleFunc("/api/health", handleHealth)
	http.HandleFunc("/api/colo-discover", handleColoDiscover)
	http.HandleFunc("/api/history", handleHistory)
	http.HandleFunc("/api/history/", handleHistory)
	http.HandleFunc("/api/history/list", handleHistoryList)
	http.HandleFunc("/api/github-upload", handleGitHubUpload)
	http.HandleFunc("/api/resolve-domain", handleResolveDomain)
	http.HandleFunc("/api/dns-upload", handleDNSUpload)
	http.HandleFunc("/api/resolve-url", handleResolveURL)
	http.HandleFunc("/api/route-info", handleRouteInfo)
	http.HandleFunc("/api/cfnb/run", handleCfnbRun)
	http.HandleFunc("/api/cfnb/run/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/cfnb/run/")
		parts := strings.SplitN(path, "/", 2)
		id := parts[0]
		if id == "" {
			http.Error(w, "missing id", 400)
			return
		}

		cfnbScansMu.RLock()
		session, ok := cfnbScans[id]
		cfnbScansMu.RUnlock()
		if !ok {
			http.Error(w, "scan not found", 404)
			return
		}

		if r.URL.Query().Has("subscribe") {
			handleCfnbProgressSSE(w, r, session)
			return
		}

		session.mu.RLock()
		status := session.status
		result := session.result
		output := session.output
		err := session.err
		session.mu.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  status,
			"results": result,
			"output":  output,
			"error":   err,
		})
	})

	http.HandleFunc("/api/cfnb/cancel/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/cfnb/cancel/")
		handleCfnbCancel(w, id)
	})

	http.HandleFunc("/api/cfnb/inline-sources/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/cfnb/inline-sources/")
		inlinePath := filepath.Join(os.TempDir(), "cfnb", "inline_"+id+".txt")
		data, err := os.ReadFile(inlinePath)
		if err != nil {
			http.Error(w, "not found", 404)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(data)
	})

	log.Printf("Vect Web UI starting on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func newScanID() string {
	id := atomic.AddInt64(&nextID, 1)
	return fmt.Sprintf("%x", time.Now().UnixNano()) + fmt.Sprintf("%04x", id)
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

	// Resolve ASN if provided
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
	// Filter by IP version
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
	ctx, cancel := context.WithCancel(context.Background())
	session := &ScanSession{
		status: "running",
		progress: ProgressData{
			Budget:  req.Budget,
		},
		cancel: cancel,
	}
	scansMu.Lock()
	scans[id] = session
	scansMu.Unlock()

	timeout, _ := time.ParseDuration(req.Timeout)
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	topN := 20
	if req.TopN > 0 {
		topN = req.TopN
	}
	cfg := engine.Config{
		Budget:          req.Budget,
		TopN:            topN,
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
		CIDRs:    cidrs,
		Probe:    probeCfg,
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
		defer cancel()
		var subs []chan ProgressData

		// Stage 1: CIDR/ASN parsing
		session.mu.Lock()
		session.progress = ProgressData{Budget: req.Budget, Stage: 1, Completed: 1}
		subs = make([]chan ProgressData, len(session.subs))
		copy(subs, session.subs)
		session.mu.Unlock()
		sendProgress(session.progress, subs)

		// Stage 2: IP sampling
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
		// Stage 4: filtering/sorting
		session.progress.Stage = 4
		session.progress.Completed = 1
		session.progress.RetainedCount = len(filtered)
		subs = make([]chan ProgressData, len(session.subs))
		copy(subs, session.subs)
		session.mu.Unlock()
		sendProgress(session.progress, subs)

		// Run download tests if requested (keep SSE open during download)
		if req.DownloadTop > 0 && len(session.result) > 0 && session.result[0].ScoreMS < 6000 {
			dlTop := req.DownloadTop
			log.Printf("download: starting %d tests on %d results", dlTop, len(session.result))
			session.mu.Lock()
			session.status = "downloading"
			session.mu.Unlock()

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
			if req.CustomDownloadEnabled && req.CustomDownloadUrl != "" {
				if u, err := url.Parse(req.CustomDownloadUrl); err == nil && u.Host != "" {
					dlCfg.SNI = u.Hostname()
					dlCfg.HostName = u.Host
					path := u.Path
					if u.RawQuery != "" {
						path += "?" + u.RawQuery
					}
					dlCfg.Path = path
					dlCfg.CustomURL = true
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
		}

		// Re-sort by comprehensive score: latency + bandwidth + download speed
		session.mu.Lock()
		sort.SliceStable(session.result, func(i, j int) bool {
			return session.result[i].ScoreMS < session.result[j].ScoreMS
		})
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

func sendProgress(progress ProgressData, subs []chan ProgressData) {
	for _, ch := range subs {
		select {
		case ch <- progress:
		default:
		}
	}
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
			session.mu.Lock()
			for i, sub := range session.subs {
				if sub == ch {
					session.subs = append(session.subs[:i], session.subs[i+1:]...)
					break
				}
			}
			session.mu.Unlock()
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
	if session.status == "running" || session.status == "downloading" {
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
			// Filter by IP version if requested
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

	// Hostname
	host, _ := os.Hostname()
	info.Hostname = host

	// Local IPs
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

	// Public IP + ISP via ip-api.com (returns full info)
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
	// Fallback to ipify if ip-api.com failed
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
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
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
	req2, err := http.NewRequest("GET", fetchURL, nil)
	if err != nil {
		http.Error(w, "invalid url: "+err.Error(), 400)
		return
	}
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
	getReq.Header.Set("User-Agent", "Vect-IP/1.49")

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

type cfnbRunRequest struct {
	Sources            []string `json:"sources"`
	CIDRs              []string `json:"cidrs"`
	IPs                []string `json:"ips"`
	GlobalMode         bool     `json:"globalMode"`
	TopN               int      `json:"topN"`
	PerCountryTopN     int      `json:"perCountryTopN"`
	BwCandidates       int      `json:"bwCandidates"`
	BwSize             float64  `json:"bwSize"`
	TcpTimeout         float64  `json:"tcpTimeout"`
	TcpProbes          int      `json:"tcpProbes"`
	MinSuccessRate     float64  `json:"minSuccessRate"`
	SocketTimeout      float64  `json:"socketTimeout"`
	Workers            int      `json:"workers"`
	SpeedWeight        float64  `json:"speedWeight"`
	HttpLatWeight      float64  `json:"httpLatWeight"`
	JitterWeight       float64  `json:"jitterWeight"`
	TcpLatWeight       float64  `json:"tcpLatWeight"`
	JitterSamples      int      `json:"jitterSamples"`
	TestAvailability   bool     `json:"testAvailability"`
	TestHttp           bool     `json:"testHttp"`
	BwWorkers          int      `json:"bwWorkers"`
	PortFilterEnabled  bool     `json:"portFilterEnabled"`
	Ports              []int    `json:"ports"`
	WhitelistEnabled   bool     `json:"whitelistEnabled"`
	WhitelistCountries []string `json:"whitelistCountries"`
	BlockedEnabled     bool     `json:"blockedEnabled"`
	BlockedCountries   []string `json:"blockedCountries"`
}

func handleCfnbCancel(w http.ResponseWriter, id string) {
	cfnbScansMu.RLock()
	session, ok := cfnbScans[id]
	cfnbScansMu.RUnlock()
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

func expandCIDR(cidr string) ([]string, error) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, err
	}
	if !p.Addr().Is4() {
		return nil, fmt.Errorf("only IPv4 CIDR supported")
	}
	var ips []string
	addr := p.Addr()
	n := 1 << (32 - p.Bits())
	for i := 0; i < n; i++ {
		ips = append(ips, addr.String())
		addr = addr.Next()
	}
	return ips, nil
}

func handleCfnbRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req cfnbRunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request: "+err.Error(), 400)
		return
	}
	if len(req.Sources) == 0 && len(req.CIDRs) == 0 && len(req.IPs) == 0 {
		http.Error(w, "at least one source, CIDR, or IP required", 400)
		return
	}

	id := fmt.Sprintf("cfnb_%d", atomic.AddInt64(&cfnbIDCounter, 1))
	_, cancel := context.WithCancel(r.Context())

	session := &CfnbSession{
		status: "running",
		subs:   make([]chan ProgressData, 0),
		cancel: cancel,
	}

	cfnbScansMu.Lock()
	cfnbScans[id] = session
	cfnbScansMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"id": id})

	go func() {
		defer func() {
			session.mu.Lock()
			if session.status == "running" {
				session.status = "completed"
			}
			session.finishedAt = time.Now()
			allSubs := session.subs
			session.subs = nil
			session.mu.Unlock()
			for _, ch := range allSubs {
				close(ch)
			}
			time.AfterFunc(5*time.Minute, func() {
				cfnbScansMu.Lock()
				delete(cfnbScans, id)
				cfnbScansMu.Unlock()
			})
		}()

		scriptDir := filepath.Join(os.TempDir(), "cfnb")
		if err := os.MkdirAll(scriptDir, 0755); err != nil {
			session.mu.Lock()
			session.err = "mkdir: " + err.Error()
			session.status = "failed"
			session.mu.Unlock()
			return
		}
		configPath := filepath.Join(scriptDir, "config.json")

		sources := make([]map[string]interface{}, len(req.Sources))
		for i, s := range req.Sources {
			sources[i] = map[string]interface{}{"url": s, "enabled": true}
		}

		// Expand CIDRs and IPs into an inline source file
		var inlineIPs []string
		for _, cidr := range req.CIDRs {
			ips, err := expandCIDR(cidr)
			if err != nil {
				session.mu.Lock()
				session.err = "expand CIDR " + cidr + ": " + err.Error()
				session.status = "failed"
				session.mu.Unlock()
				return
			}
			for _, ip := range ips {
				inlineIPs = append(inlineIPs, ip+":443")
			}
		}
		for _, ip := range req.IPs {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				if strings.Contains(ip, ":") {
					inlineIPs = append(inlineIPs, ip)
				} else {
					inlineIPs = append(inlineIPs, ip+":443")
				}
			}
		}
		if len(inlineIPs) > 0 {
			inlinePath := filepath.Join(scriptDir, "inline_"+id+".txt")
			if err := os.WriteFile(inlinePath, []byte(strings.Join(inlineIPs, "\n")), 0644); err != nil {
				session.mu.Lock()
				session.err = "write inline sources: " + err.Error()
				session.status = "failed"
				session.mu.Unlock()
				return
			}
			sources = append(sources, map[string]interface{}{"url": "http://127.0.0.1:" + cfnbServerPort + "/api/cfnb/inline-sources/" + id, "enabled": true})
		}

		cfg := map[string]interface{}{
			"USE_GLOBAL_MODE":                req.GlobalMode,
			"GLOBAL_TOP_N":                   req.TopN,
			"PER_COUNTRY_TOP_N":              intMax(1, req.PerCountryTopN),
			"BANDWIDTH_CANDIDATES":           req.BwCandidates,
			"TCP_PROBES":                     intMax(1, req.TcpProbes),
			"MIN_SUCCESS_RATE":               req.MinSuccessRate,
			"TCP_LATENCY_WEIGHT":             req.TcpLatWeight,
			"TIMEOUT":                        req.TcpTimeout,
			"SOCKET_DEFAULT_TIMEOUT":         req.SocketTimeout,
			"PROGRESS_PRINT_INTERVAL":        1,
			"FILTER_COUNTRIES_ENABLED":       req.WhitelistEnabled,
			"ALLOWED_COUNTRIES":              req.WhitelistCountries,
			"PRE_FILTER_BLOCKED_ENABLED":     true,
			"PRE_FILTER_BLOCKED_COUNTRIES":   []string{"CN"},
			"PRE_FILTER_PORT_ENABLED":        req.PortFilterEnabled,
			"PRE_FILTER_PORTS":               req.Ports,
			"ENABLE_WXPUSHER":                false,
			"CF_ENABLED":                     false,
			"GITHUB_SYNC_MAX_RETRIES":        0,
			"TEST_AVAILABILITY":              req.TestAvailability,
			"AVAILABILITY_CHECK_API":         "https://api.090227.xyz/check",
			"AVAILABILITY_TIMEOUT":           3,
			"AVAILABILITY_CONNECT_TIMEOUT":   3,
			"AVAILABILITY_RETRY_MAX":         1,
			"AVAILABILITY_RETRY_DELAY":       3,
			"AVAILABILITY_INNER_RETRY_ENABLED": true,
			"AVAILABILITY_INNER_RETRY_MAX":   1,
			"AVAILABILITY_INNER_RETRY_DELAY": 3,
			"HTTP_TEST_ENABLED":              req.TestHttp,
			"HTTP_TEST_TIMEOUT":              3,
			"HTTP_TEST_CONNECT_TIMEOUT":      3,
			"HTTP_TEST_MAX_ROUNDS":           1,
			"HTTP_TEST_ROUND_DELAY":          3,
			"HTTP_TEST_INNER_RETRY_ENABLED":  true,
			"HTTP_TEST_MAX_RETRIES":          1,
			"HTTP_TEST_RETRY_DELAY":          3,
			"HTTP_TEST_METHOD":               "HEAD",
			"HTTP_LATENCY_WEIGHT":            req.HttpLatWeight,
			"JITTER_WEIGHT":                  req.JitterWeight,
			"HTTP_JITTER_SAMPLES":            intMax(1, req.JitterSamples),
			"FILTER_IPV6_AVAILABILITY":       false,
			"FILTER_BLOCKED_COUNTRIES_ENABLED": req.BlockedEnabled,
			"BLOCKED_COUNTRIES":              req.BlockedCountries,
			"DNS_IP_RISK_FILTER_ENABLED":     false,
			"DNS_UPDATE_TARGET_COUNT":        15,
			"BANDWIDTH_SIZE_MB":              req.BwSize,
			"BANDWIDTH_TIMEOUT":              3,
			"BANDWIDTH_RETRY_MAX":            1,
			"BANDWIDTH_RETRY_DELAY":          3,
			"BANDWIDTH_URL_TEMPLATE":         "https://speed.cloudflare.com/__down?bytes={bytes}",
			"BANDWIDTH_PROCESS_BUFFER":       2,
			"BANDWIDTH_CONNECT_TIMEOUT":      3,
			"SPEED_WEIGHT":                   req.SpeedWeight,
			"IP_CALIBRATION_ENABLED":         false,
			"MAX_WORKERS":                    intMax(1, req.Workers),
			"AVAILABILITY_WORKERS":           32,
			"FALLBACK_WORKERS":               32,
			"BANDWIDTH_WORKERS":              intMax(1, req.BwWorkers),
			"HTTP_TEST_WORKERS":              32,
			"ADDITIONAL_SOURCES":             sources,
			"OUTPUT_FILE":                    "ip.txt",
			"ENABLE_LOGGING":                 false,
			"FORCE_DIRECT":                   false,
			"IP_TXT_SHOW_BANDWIDTH":          true,
			"IP_TXT_SHOW_HTTP_LATENCY":       true,
			"IP_TXT_SHOW_HTTP_JITTER":        true,
			"IP_TXT_SHOW_LATENCY":            true,
			"AD_HEADER_ENABLED":              false,
			"AD_FOOTER_ENABLED":              false,
			"AD_PERLINE_ENABLED":             false,
		}

		cfgData, _ := json.MarshalIndent(cfg, "", "  ")
		if err := os.WriteFile(configPath, cfgData, 0644); err != nil {
			session.mu.Lock()
			session.err = "write config: " + err.Error()
			session.status = "failed"
			session.mu.Unlock()
			return
		}

		// Check python3 availability and script existence
		pythonBin := ""
		for _, name := range []string{"python3", "python"} {
			if p, err := exec.LookPath(name); err == nil {
				pythonBin = p
				break
			}
		}
		if pythonBin == "" {
			session.mu.Lock()
			session.err = "python3 not found: CFNB requires Python on this device"
			session.status = "failed"
			session.mu.Unlock()
			return
		}
		scriptPath := filepath.Join(scriptDir, "main.py")
		if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
			session.mu.Lock()
			session.err = "CFNB script not found at " + scriptPath + ": please install CFNB package first"
			session.status = "failed"
			session.mu.Unlock()
			return
		}

		sendCfnbProgress(session, ProgressData{Stage: 1, Nodes: 0, Completed: 0, Budget: 100})

		pctx, pcancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer pcancel()

		cmd := exec.CommandContext(pctx, pythonBin, "main.py")
		cmd.Dir = scriptDir
		cmd.Env = append(os.Environ(), "PYTHONUNBUFFERED=1")

		stdout, _ := cmd.StdoutPipe()
		stderr, _ := cmd.StderrPipe()

		if err := cmd.Start(); err != nil {
			session.mu.Lock()
			session.err = err.Error()
			session.status = "failed"
			session.mu.Unlock()
			return
		}

		output := ""
		done := make(chan bool)
		go func() {
			scanner := bufio.NewScanner(stdout)
			scanner.Split(scanLinesOrCR)
			scanner.Buffer(make([]byte, 1024*64), 1024*64)
			for scanner.Scan() {
				line := scanner.Text()
				line = strings.TrimRight(line, "\r")
				if line == "" {
					continue
				}
				output += line + "\n"
				parseCfnbProgress(line, session)
			}
			done <- true
		}()

		stderrOutput := ""
		go func() {
			scanner := bufio.NewScanner(stderr)
			scanner.Buffer(make([]byte, 1024*64), 1024*64)
			for scanner.Scan() {
				line := scanner.Text()
				stderrOutput += line + "\n"
				parseCfnbProgress(line, session)
			}
		}()

		cmd.Wait()
		<-done

		fullOutput := output + stderrOutput

		var results []map[string]interface{}
		ipTxtPath := filepath.Join(scriptDir, "ip.txt")
		if data, err := os.ReadFile(ipTxtPath); err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "0.0.0.0") {
					continue
				}
				parts := strings.SplitN(line, "#", 2)
				ipport := parts[0]
				label := ""
				speedVal := ""
				httpLatencyVal := ""
				httpJitterVal := ""
				tcpLatencyVal := ""
				if len(parts) > 1 {
					suffix := strings.TrimSpace(parts[1])
					fields := strings.Fields(suffix)
					if len(fields) >= 1 {
						label = fields[0]
						if len(label) == 2 {
							// Keep original 2-letter country code, no 3-letter mapping
						}
						// Parse metric pairs (value unit) after country code
						// Possible format: speed Mbps http_latency ms http_jitter ms tcp_latency ms
						// If bandwidth test failed, speed field is absent
						for fi := 1; fi+1 < len(fields); fi += 2 {
							val := fields[fi]
							unit := fields[fi+1]
							if unit == "Mbps" {
								speedVal = val + " " + unit
							} else if unit == "ms" {
								if httpLatencyVal == "" {
									httpLatencyVal = val + " " + unit
								} else if httpJitterVal == "" {
									httpJitterVal = val + " " + unit
								} else if tcpLatencyVal == "" {
									tcpLatencyVal = val + " " + unit
								}
							}
						}
					}
				}
				ipPortParts := strings.SplitN(ipport, ":", 2)
				ip := ipport
				port := "443"
				if len(ipPortParts) == 2 {
					ip = ipPortParts[0]
					port = ipPortParts[1]
				}
				results = append(results, map[string]interface{}{
					"ip":           ip,
					"port":         port,
					"label":        label,
					"speed":        speedVal,
					"http_latency": httpLatencyVal,
					"http_jitter":  httpJitterVal,
					"tcp_latency":  tcpLatencyVal,
				})
			}
		}

		session.mu.Lock()
		session.output = fullOutput
		session.result = results
		session.status = "completed"
		session.progress = ProgressData{Stage: 5, Completed: 100, Budget: 100}
		subs := make([]chan ProgressData, len(session.subs))
		copy(subs, session.subs)
		session.mu.Unlock()
		sendProgress(session.progress, subs)
	}()
}

func parseCfnbProgress(line string, session *CfnbSession) {
	p := ProgressData{Completed: 0, Budget: 100}
	switch {
	case strings.Contains(line, "正在请求数据源"):
		p.Stage = 1
		p.Nodes = 0
	case strings.Contains(line, "解析出"):
		p.Stage = 1
		p.Completed = 100
		p.Nodes = 0
		if idx := strings.Index(line, "解析出"); idx >= 0 {
			rest := line[idx+len("解析出"):]
			rest = strings.TrimSpace(rest)
			if spaceIdx := strings.Index(rest, " "); spaceIdx >= 0 {
				if n, err := strconv.Atoi(strings.TrimSpace(rest[:spaceIdx])); err == nil {
					p.Nodes = n
				}
			}
		}
	case strings.Contains(line, "开始 TCP 连接测试"):
		p.Stage = 2
		p.Completed = 0
		p.Nodes = 0
	case strings.Contains(line, "TCP 测试完成"):
		p.Stage = 2
		p.Completed = 100
	case strings.Contains(line, "[可用性检测] 进度"):
		p.Stage = 3
		if idx := strings.Index(line, "("); idx >= 0 {
			if pctIdx := strings.Index(line[idx:], "%)"); pctIdx >= 0 {
				pctStr := strings.TrimSpace(line[idx+1 : idx+pctIdx])
				if pct, err := strconv.ParseFloat(pctStr, 64); err == nil {
					p.Completed = int(pct)
				}
			}
		}
	case strings.Contains(line, "可用性检测通过"):
		p.Stage = 3
		p.Completed = 100
	case strings.Contains(line, "[HTTP检测] 进度"):
		p.Stage = 4
		if idx := strings.Index(line, "("); idx >= 0 {
			if pctIdx := strings.Index(line[idx:], "%)"); pctIdx >= 0 {
				pctStr := strings.TrimSpace(line[idx+1 : idx+pctIdx])
				if pct, err := strconv.ParseFloat(pctStr, 64); err == nil {
					p.Completed = int(pct)
				}
			}
		}
	case strings.Contains(line, "HTTP检测通过"):
		p.Stage = 4
		p.Completed = 100
	case strings.Contains(line, "[带宽测速] 进度"):
		p.Stage = 5
		if idx := strings.Index(line, "("); idx >= 0 {
			if pctIdx := strings.Index(line[idx:], "%)"); pctIdx >= 0 {
				pctStr := strings.TrimSpace(line[idx+1 : idx+pctIdx])
				if pct, err := strconv.ParseFloat(pctStr, 64); err == nil {
					p.Completed = int(pct)
				}
			}
		}
	case strings.Contains(line, "开始带宽测速"):
		p.Stage = 5
		p.Completed = 0
	case strings.Contains(line, "进度：") && !strings.Contains(line, "Token") && !strings.Contains(line, "备用API"):
		p.Stage = 2
		if idx := strings.Index(line, "进度："); idx >= 0 {
			rest := line[idx+9:]
			if slashIdx := strings.Index(rest, "/"); slashIdx >= 0 {
				if completed, err := strconv.Atoi(strings.TrimSpace(rest[:slashIdx])); err == nil {
					rest2 := rest[slashIdx+1:]
					if spaceIdx := strings.Index(rest2, " "); spaceIdx >= 0 {
						if total, err := strconv.Atoi(strings.TrimSpace(rest2[:spaceIdx])); err == nil && total > 0 {
							p.Completed = completed * 100 / total
						}
					}
				}
			}
		}
	default:
		if strings.Contains(line, "当前模式") || strings.Contains(line, "合并后总计") || strings.Contains(line, "前置端口过滤") || strings.Contains(line, "前置黑名单过滤") || strings.Contains(line, "国家过滤") || strings.Contains(line, "没有获取到任何") || strings.Contains(line, "通过成功率筛选") || strings.Contains(line, "各国家候选池") || strings.Contains(line, "没有候选节点") {
			return
		}
		return
	}
	sendCfnbProgress(session, p)
}

func sendCfnbProgress(session *CfnbSession, p ProgressData) {
	session.mu.Lock()
	session.progress = p
	subs := make([]chan ProgressData, len(session.subs))
	copy(subs, session.subs)
	session.mu.Unlock()
	sendProgress(p, subs)
}

func handleCfnbProgressSSE(w http.ResponseWriter, r *http.Request, session *CfnbSession) {
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
			session.mu.Lock()
			for i, sub := range session.subs {
				if sub == ch {
					session.subs = append(session.subs[:i], session.subs[i+1:]...)
					break
				}
			}
			session.mu.Unlock()
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

func intMax(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func scanLinesOrCR(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			return i + 1, data[:i], nil
		}
		if data[i] == '\r' {
			if i+1 < len(data) && data[i+1] == '\n' {
				return i + 2, data[:i], nil
			}
			return i + 1, data[:i], nil
		}
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}