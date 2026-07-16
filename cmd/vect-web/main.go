package main

import (
	"bufio"
	"context"
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
	"regexp"
	"path/filepath"
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
	CIDRs           []string `json:"cidrs"`
	ASN             int      `json:"asn"`
	Budget          int      `json:"budget"`
	Concurrency     int      `json:"concurrency"`
	Heads           int      `json:"heads"`
	Beam            int      `json:"beam"`
	Timeout         string   `json:"timeout"`
	Host            string   `json:"host"`
	Path            string   `json:"path"`
	Rounds          int      `json:"rounds"`
	SkipFirst       int      `json:"skipFirst"`
	DownloadTop     int      `json:"downloadTop"`
	DownloadMode    string   `json:"downloadMode"`
	ColoAllow       string   `json:"coloAllow"`
	ColoExclude     string   `json:"coloExclude"`
	SplitStepV4     int      `json:"splitStepV4"`
	SplitStepV6     int      `json:"splitStepV6"`
	DiversityWeight float64  `json:"diversityWeight"`
	SplitInterval       int      `json:"splitInterval"`
	MinSamplesSplit     int      `json:"minSamplesSplit"`
	MaxBitsV4           int      `json:"maxBitsV4"`
	MaxBitsV6           int      `json:"maxBitsV6"`
	Seed                int64    `json:"seed"`
	IPVersion           int      `json:"ipVersion"`
	TopN                int      `json:"topN"`
	CustomDownloadUrl   string   `json:"customDownloadUrl"`
	CustomDownloadEnabled bool   `json:"customDownloadEnabled"`
	DownloadBytes   int64    `json:"downloadBytes"`
	DownloadTimeout int      `json:"downloadTimeout"`
}

type ScanStatus struct {
	ID        string          `json:"id"`
	Status    string          `json:"status"`
	Progress  *ProgressData   `json:"progress,omitempty"`
	Result    []engine.TopResult `json:"result,omitempty"`
	Error     string          `json:"error,omitempty"`
}

type ProgressData struct {
	Completed   int     `json:"completed"`
	Budget      int     `json:"budget"`
	BestScore   float64 `json:"bestScore"`
	BestIP      string  `json:"bestIP"`
	BestPrefix  string  `json:"bestPrefix"`
	ElapsedMS   int64   `json:"elapsedMS"`
	Nodes       int     `json:"nodes"`
	Stage       int     `json:"stage"`
	DownloadIP  string  `json:"downloadIp,omitempty"`
	DownloadMbps float64 `json:"downloadMbps,omitempty"`
}

type ScanSession struct {
	mu       sync.RWMutex
	status   string
	progress ProgressData
	result   []engine.TopResult
	err      string
	cancel   context.CancelFunc
	subs     []chan ProgressData
}

var (
	scans     = make(map[string]*ScanSession)
	scansMu   sync.RWMutex
	nextID    int64
	historyMu sync.Mutex
)

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
	sort.Slice(dlOK, func(i, j int) bool { return false }) // maintain order

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

	http.Handle("/", noCache(http.FileServer(http.FS(web.FS))))

	http.HandleFunc("/api/scan", handleScan)
	http.HandleFunc("/api/scan/", handleScanByID)
	http.HandleFunc("/api/resolve-asn/", handleResolveASN)
	http.HandleFunc("/api/cancel/", handleCancel)
	http.HandleFunc("/api/local-ip", handleLocalIP)
	http.HandleFunc("/api/traceroute/", handleTraceroute)
	http.HandleFunc("/api/route-type/", handleRouteType)
	http.HandleFunc("/api/route-type", handleBatchRouteType)
	http.HandleFunc("/api/health", handleHealth)
	http.HandleFunc("/api/colo-discover", handleColoDiscover)
	http.HandleFunc("/api/history", handleHistory)
	http.HandleFunc("/api/history/", handleHistory)
	http.HandleFunc("/api/dns-upload", handleDNSUpload)
	http.HandleFunc("/api/resolve-url", handleResolveURL)

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
	log.Printf("scan request: downloadTop=%d budget=%d cidrs=%d", req.DownloadTop, req.Budget, len(req.CIDRs))

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
	session := &ScanSession{
		status: "running",
		progress: ProgressData{
			Budget:  req.Budget,
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
		Timeout:    timeout,
		SNI:        req.Host,
		HostHeader: req.Host,
		Path:       req.Path,
		Rounds:     req.Rounds,
		SkipFirst:  req.SkipFirst,
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
			session.status = "failed"
			session.err = err.Error()
		} else {
			session.status = "completed"
			session.result = resp.Top
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
		subs = make([]chan ProgressData, len(session.subs))
		copy(subs, session.subs)
		session.mu.Unlock()
		sendProgress(session.progress, subs)

		// Run download tests if requested (keep SSE open during download)
		if req.DownloadTop > 0 && len(session.result) > 0 {
			log.Printf("download: starting %d tests on %d results", req.DownloadTop, len(session.result))
			session.mu.Lock()
			session.status = "downloading"
			session.mu.Unlock()

			dlTop := req.DownloadTop
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
					dlCfg.SNI = u.Host
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
			maxTests := dlTop
			if req.DownloadMode == "sequential" {
				maxTests = len(session.result)
			}

			successCount := 0
			for i := 0; i < maxTests && successCount < dlTop; i++ {
				r := &session.result[i]
				var dr probe.DownloadResult
				for attempt := 0; attempt < 3; attempt++ {
					dlCtx, dlCancel := context.WithTimeout(ctx, time.Duration(dlTimeout)*time.Second)
					dr = dlp.Download(dlCtx, r.IP)
					dlCancel()
					if dr.OK {
						break
					}
				}
				r.DownloadOK = dr.OK
				r.DownloadBytes = dr.Bytes
				r.DownloadMS = dr.TotalMS
				r.DownloadMbps = dr.Mbps
				r.DownloadPeakMbps = dr.PeakMbps
				r.DownloadError = dr.Error
				if dr.OK {
					successCount++
				}
				// Send download progress with per-IP details
				session.mu.Lock()
				session.progress.Stage = 5
				session.progress.Completed = successCount
				session.progress.Budget = dlTop
				session.progress.DownloadIP = r.IP.String()
				session.progress.DownloadMbps = dr.Mbps
				dlSubs := make([]chan ProgressData, len(session.subs))
				copy(dlSubs, session.subs)
				session.mu.Unlock()
				sendProgress(session.progress, dlSubs)
			}
		}

		session.mu.Lock()
		session.status = "completed"
		session.mu.Unlock()

		// Close SSE channels after all processing is done
		session.mu.Lock()
		session.subs = nil
		session.mu.Unlock()
		for _, ch := range subs {
			close(ch)
		}

		// Fill route types for all results
		if len(session.result) > 0 {
			ips := make([]string, len(session.result))
			for i, r := range session.result {
				ips[i] = r.IP.String()
			}

			rctx, rcancel := context.WithTimeout(context.Background(), 120*time.Second)
			routeResults := batchClassifyRoutes(rctx, ips)
			rcancel()

			session.mu.Lock()
			for i := range session.result {
				if ri, ok := routeResults[session.result[i].IP.String()]; ok {
					if session.result[i].Trace == nil {
						session.result[i].Trace = make(map[string]string)
					}
					routeLabel := "Normal"
					routeLine := ""
					if ri != nil {
						routeLabel = ri.RouteType
						routeLine = ri.RouteLine
					}
					if routeLine != "" {
						session.result[i].Trace["route"] = fmt.Sprintf("%s｜%s｜%s", ri.Org, routeLine, routeLabel)
					} else {
						session.result[i].Trace["route"] = routeLabel
					}
				}
			}
			session.mu.Unlock()
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
	status := ScanStatus{
		ID:       id,
		Status:   session.status,
		Progress: &session.progress,
		Error:    session.err,
	}
	if session.status == "completed" {
		status.Result = session.result
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
	session.subs = append(session.subs, ch)
	if session.status != "running" {
		ch <- session.progress
	}
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

func resolveASN(asn int, ipVersion int) ([]string, error) {
	url := fmt.Sprintf("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS%d", asn)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("RIPE API: %w", err)
	}
	defer resp.Body.Close()

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

var premiumASNs = map[int]string{
	4809:  "CN2",
	9929:  "CUII",
	58807: "CMIN2",
}

var optimizedASNs = map[int]string{
	58453: "CMI",
	4134:  "163",
	4837:  "169",
	4538:  "CERNET",
	24445: "CMHK",
	132203: "CNI",
}

type RouteInfo struct {
	ASN       int    `json:"asn"`
	Org       string `json:"org"`
	RouteType string `json:"routeType"`
	RouteLine string `json:"routeLine"`
}

func classifyRoute(asn int) (routeType, routeLine string) {
	if line, ok := premiumASNs[asn]; ok {
		return "Premium", line
	}
	if line, ok := optimizedASNs[asn]; ok {
		return "Optimized", line
	}
	return "Normal", ""
}

// hopPrefixPatterns matches IP prefixes in traceroute hops to identify route lines.
// Models IP-Tidy's _HOP_PATTERNS / _ROUTE_TABLE logic.
var hopPrefixPatterns = []struct {
	prefix    string
	line      string
	routeType string
}{
	{"59.43.", "CN2", "Premium"},     // China Telecom CN2 backbone
	{"223.120.", "CUII", "Premium"},  // China Unicom CUII backbone
	{"219.158.", "CMI", "Optimized"}, // China Mobile International
	{"202.97.", "163", "Optimized"},  // China Telecom 163 backbone
}

func matchHopPrefix(ip string) (routeType, line string) {
	for _, p := range hopPrefixPatterns {
		if strings.HasPrefix(ip, p.prefix) {
			return p.routeType, p.line
		}
	}
	return "", ""
}

func lookupRoute(ctx context.Context, ip string) *RouteInfo {
	client := &http.Client{Timeout: 5 * time.Second}
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=query,as,asname,org,isp", ip)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var data struct {
		AS     string `json:"as"`
		ASName string `json:"asname"`
		Org    string `json:"org"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil
	}

	asn := 0
	fmt.Sscanf(data.AS, "AS%d", &asn)
	routeType, routeLine := classifyRoute(asn)
	return &RouteInfo{
		ASN:       asn,
		Org:       data.Org,
		RouteType: routeType,
		RouteLine: routeLine,
	}
}

func batchClassifyRoutes(ctx context.Context, ips []string) map[string]*RouteInfo {
	results := make(map[string]*RouteInfo)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)

	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			info := classifyRouteByTrace(ctx, ip)
			mu.Lock()
			results[ip] = info
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	return results
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
	}
	if v, ok := m[isp]; ok {
		return v
	}
	prefix := map[string]string{
		"Chinanet":   "中国电信",
		"China169":   "中国联通",
		"CMNET":      "中国移动",
		"CNCN":       "中国网通",
		"BGP.CN":     "中国BGP",
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

type TracerouteHop struct {
	Hop         int    `json:"hop"`
	IP          string `json:"ip"`
	MS          string `json:"ms"`
	Lost        bool   `json:"lost"`
	ASN         string `json:"asn,omitempty"`
	Country     string `json:"country,omitempty"`
	CountryCode string `json:"countryCode,omitempty"`
	City        string `json:"city,omitempty"`
	ISP         string `json:"isp,omitempty"`
	RouteType   string `json:"routeType,omitempty"`
	RouteLine   string `json:"routeLine,omitempty"`
}

func handleTraceroute(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimPrefix(r.URL.Path, "/api/traceroute/")
	if ip == "" {
		http.Error(w, "missing IP", 400)
		return
	}

	// Validate IP
	if parsed := net.ParseIP(ip); parsed == nil {
		http.Error(w, "invalid IP", 400)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	hops := runTraceroute(ctx, ip)

	// Enrich hops that lack ASN data (system traceroute fallback path)
	hops = enrichHops(ctx, hops)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(hops)
}

func runTraceroute(ctx context.Context, ip string) []TracerouteHop {
	// Try NextTrace first for best results (TCP mode, GeoIP, ASN)
	hops := runNextTrace(ctx, ip)
	if hops != nil {
		return hops
	}

	// Fall back to standard traceroute with TCP mode (-T -p 443)
	cmd := exec.CommandContext(ctx, "traceroute", "-T", "-p", "443", "-n", "-q", "1", "-w", "2", ip)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil
	}
	if err := cmd.Start(); err != nil {
		return nil
	}

	var scanner *bufio.Scanner
	for scanner = bufio.NewScanner(stdout); scanner.Scan(); {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		hopNum, err := strconv.Atoi(parts[0])
		if err != nil {
			continue
		}
		hopIP := parts[1]
		if hopIP == "*" {
			hops = append(hops, TracerouteHop{Hop: hopNum, Lost: true})
			continue
		}
		ms := ""
		if len(parts) >= 3 {
			ms = strings.TrimSuffix(parts[2], "ms")
		}
		hops = append(hops, TracerouteHop{Hop: hopNum, IP: hopIP, MS: ms})
	}
	cmd.Wait()
	return hops
}

// enrichHops fills in ASN, Country, City, ISP for hops that lack them.
// Uses concurrent ip-api.com lookups with caching.
func enrichHops(ctx context.Context, hops []TracerouteHop) []TracerouteHop {
	type hopInfo struct {
		ASN       string
		Country   string
		CountryCode string
		City      string
		ISP       string
		RouteType string
		RouteLine string
	}
	cache := make(map[string]*hopInfo)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)

	for i := range hops {
		if hops[i].Lost || hops[i].IP == "" || hops[i].ASN != "" {
			continue
		}
		ip := hops[i].IP
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			mu.Lock()
			if cached, ok := cache[ip]; ok {
				mu.Unlock()
				if cached != nil {
					hops[i].ASN = cached.ASN
					hops[i].Country = cached.Country
					hops[i].CountryCode = cached.CountryCode
					hops[i].City = cached.City
					hops[i].ISP = cached.ISP
					hops[i].RouteType = cached.RouteType
					hops[i].RouteLine = cached.RouteLine
				}
				return
			}
			cache[ip] = nil // mark in-progress
			mu.Unlock()

			sem <- struct{}{}
			defer func() { <-sem }()

			client := &http.Client{Timeout: 3 * time.Second}
			url := fmt.Sprintf("http://ip-api.com/json/%s?fields=query,as,asname,org,isp,country,countryCode,city", ip)
			req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			var data struct {
				Query       string `json:"query"`
				AS          string `json:"as"`
				Org         string `json:"org"`
				ISP         string `json:"isp"`
				Country     string `json:"country"`
				CountryCode string `json:"countryCode"`
				City        string `json:"city"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
				return
			}

			asn := 0
			fmt.Sscanf(data.AS, "AS%d", &asn)
			routeType, routeLine := classifyRoute(asn)

			info := &hopInfo{
				ASN:         data.AS,
				Country:     data.Country,
				CountryCode: data.CountryCode,
				City:        data.City,
				ISP:         data.Org,
				RouteType:   routeType,
				RouteLine:   routeLine,
			}

			mu.Lock()
			cache[ip] = info
			hops[i].ASN = info.ASN
			hops[i].Country = info.Country
			hops[i].CountryCode = data.CountryCode
			hops[i].City = info.City
			hops[i].ISP = info.ISP
			hops[i].RouteType = info.RouteType
			hops[i].RouteLine = info.RouteLine
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	return hops
}

type nextTraceGeo struct {
	ASN     string `json:"ASN"`
	Country string `json:"Country"`
	City    string `json:"City"`
	Owner   string `json:"Owner"`
}

type nextTraceHop struct {
	Success bool           `json:"Success"`
	Address *string        `json:"Address"`
	TTL     int            `json:"TTL"`
	RTT     float64        `json:"RTT"`
	Geo     *nextTraceGeo `json:"Geo"`
}

type nextTraceResult struct {
	Hops [][]nextTraceHop `json:"Hops"`
}

func runNextTrace(ctx context.Context, ip string) []TracerouteHop {
	cmd := exec.CommandContext(ctx, "nexttrace", "-T", "-p", "443", "-j", "-m", "30", "-q", "1", "--timeout", "3", ip)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil
	}
	if err := cmd.Start(); err != nil {
		return nil
	}

	var output []byte
	if output, err = io.ReadAll(stdout); err != nil {
		cmd.Wait()
		return nil
	}
	cmd.Wait()

	var result nextTraceResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil
	}

	var hops []TracerouteHop
	for _, hopGroup := range result.Hops {
		if len(hopGroup) == 0 {
			continue
		}
		h := hopGroup[0]
		hop := TracerouteHop{Hop: h.TTL}
		if !h.Success || h.Address == nil {
			hop.Lost = true
		} else {
			hop.IP = *h.Address
			hop.MS = fmt.Sprintf("%.2f", h.RTT)
			if h.Geo != nil {
				hop.ASN = h.Geo.ASN
				hop.Country = h.Geo.Country
				hop.City = h.Geo.City
				hop.ISP = h.Geo.Owner
				asn := 0
				fmt.Sscanf(h.Geo.ASN, "AS%d", &asn)
				if asn > 0 {
					hop.RouteType, hop.RouteLine = classifyRoute(asn)
				}
			}
		}
		hops = append(hops, hop)
	}
	if len(hops) > 0 {
		return hops
	}
	return nil
}

func classifyRouteByTrace(ctx context.Context, ip string) *RouteInfo {
	cmd := exec.CommandContext(ctx, "nexttrace", "-T", "-p", "443", "-j", "-m", "30", "-q", "1", "--timeout", "5", ip)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil
	}
	if err := cmd.Start(); err != nil {
		return nil
	}
	var output []byte
	if output, err = io.ReadAll(stdout); err != nil {
		cmd.Wait()
		return nil
	}
	cmd.Wait()

	var result nextTraceResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil
	}

	// Collect all ASNs and hop IPs along the path
	seenASNs := make(map[int]bool)
	var lastASN int
	var lastOwner string
	premiumFound := ""
	optimizedFound := ""
	for _, hopGroup := range result.Hops {
		if len(hopGroup) == 0 {
			continue
		}
		h := hopGroup[0]
		if h.Geo != nil && h.Geo.ASN != "" {
			asn := 0
			fmt.Sscanf(h.Geo.ASN, "AS%d", &asn)
			if asn > 0 {
				seenASNs[asn] = true
				lastASN = asn
				lastOwner = h.Geo.Owner
			}
		}
		// Check hop IP prefix patterns (IP-Tidy style _HOP_PATTERNS)
		if h.Address != nil && *h.Address != "" {
			if rt, line := matchHopPrefix(*h.Address); rt != "" {
				if rt == "Premium" {
					premiumFound = line
				} else if rt == "Optimized" && premiumFound == "" {
					optimizedFound = line
				}
			}
		}
	}

	// Classify: ASN check first, then IP prefix patterns
	if premiumFound == "" {
		for asn := range seenASNs {
			if line, ok := premiumASNs[asn]; ok {
				premiumFound = line
				break
			}
		}
	}
	if premiumFound == "" && optimizedFound == "" {
		for asn := range seenASNs {
			if line, ok := optimizedASNs[asn]; ok {
				optimizedFound = line
				break
			}
		}
	}

	if premiumFound != "" {
		return &RouteInfo{ASN: lastASN, Org: lastOwner, RouteType: "Premium", RouteLine: premiumFound}
	}
	if optimizedFound != "" {
		return &RouteInfo{ASN: lastASN, Org: lastOwner, RouteType: "Optimized", RouteLine: optimizedFound}
	}

	// Fall back to destination IP ASN
	return lookupRoute(ctx, ip)
}

func handleRouteType(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimPrefix(r.URL.Path, "/api/route-type/")
	if ip == "" {
		http.Error(w, "missing IP", 400)
		return
	}
	if parsed := net.ParseIP(ip); parsed == nil {
		http.Error(w, "invalid IP", 400)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	info := lookupRoute(ctx, ip)
	if info == nil {
		http.Error(w, "route lookup failed", 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

func handleBatchRouteType(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IPs []string `json:"ips"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	if len(req.IPs) == 0 {
		json.NewEncoder(w).Encode(map[string]*RouteInfo{})
		return
	}

	results := make(map[string]*RouteInfo)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for _, ip := range req.IPs {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
			defer cancel()
			info := lookupRoute(ctx, ip)
			mu.Lock()
			results[ip] = info
			mu.Unlock()
		}(ip)
	}
	wg.Wait()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
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
	u, err := url.Parse(req.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		http.Error(w, "invalid url", 400)
		return
	}

	client := &http.Client{Timeout: 30 * time.Second}
	req2, _ := http.NewRequest("GET", req.URL, nil)
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

	ipRe := regexp.MustCompile(`^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)
	var cidrs []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		m := ipRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ip := m[1]
		rest := strings.TrimSpace(line[len(m[0]):])
		cidr := ip + "/24"
		if strings.HasPrefix(rest, "/") {
			cidr = line
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