package main

import (
	"bufio"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yu-929/Vect-IP/internal/engine"
	"github.com/yu-929/Vect-IP/internal/probe"
)

//go:embed web
var webFS embed.FS

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
	IPVersion       int      `json:"ipVersion"`
}

type ScanStatus struct {
	ID        string          `json:"id"`
	Status    string          `json:"status"`
	Progress  *ProgressData   `json:"progress,omitempty"`
	Result    []engine.TopResult `json:"result,omitempty"`
	Error     string          `json:"error,omitempty"`
}

type ProgressData struct {
	Completed  int     `json:"completed"`
	Budget     int     `json:"budget"`
	BestScore  float64 `json:"bestScore"`
	BestIP     string  `json:"bestIP"`
	BestPrefix string  `json:"bestPrefix"`
	ElapsedMS  int64   `json:"elapsedMS"`
	Nodes      int     `json:"nodes"`
	Stage      int     `json:"stage"`
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
	scans   = make(map[string]*ScanSession)
	scansMu sync.RWMutex
	nextID  int64
)

func main() {
	port := "8080"
	if p := os.Getenv("PORT"); p != "" {
		port = p
	}

	subFS, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatal(err)
	}
	http.Handle("/", http.FileServer(http.FS(subFS)))

	http.HandleFunc("/api/scan", handleScan)
	http.HandleFunc("/api/scan/", handleScanByID)
	http.HandleFunc("/api/resolve-asn/", handleResolveASN)
	http.HandleFunc("/api/cancel/", handleCancel)
	http.HandleFunc("/api/local-ip", handleLocalIP)
	http.HandleFunc("/api/traceroute/", handleTraceroute)

	log.Printf("Vect Web UI starting on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func newScanID() string {
	id := atomic.AddInt64(&nextID, 1)
	return fmt.Sprintf("%x", time.Now().UnixNano()) + fmt.Sprintf("%04x", id)
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request: "+err.Error(), 400)
		return
	}

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

	cfg := engine.Config{
		Budget:          req.Budget,
		TopN:            20,
		Concurrency:     req.Concurrency,
		Heads:           req.Heads,
		Beam:            req.Beam,
		SplitStepV4:     req.SplitStepV4,
		SplitStepV6:     req.SplitStepV6,
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
	if req.SplitStepV4 <= 0 {
		cfg.SplitStepV4 = 2
	}
	if req.SplitStepV6 <= 0 {
		cfg.SplitStepV6 = 4
	}

	if req.ColoAllow != "" {
		cfg.ColoAllow = strings.Split(req.ColoAllow, ",")
	}
	if req.ColoExclude != "" {
		cfg.ColoBlock = strings.Split(req.ColoExclude, ",")
	}

go func() {
		// Stage 1: CIDR/ASN parsing
		session.mu.Lock()
		session.progress = ProgressData{Budget: req.Budget, Stage: 1, Completed: 1}
		subs := make([]chan ProgressData, len(session.subs))
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
		// Stage 4: filtering/sorting
		session.progress.Stage = 4
		session.progress.Completed = 1
		subs = make([]chan ProgressData, len(session.subs))
		copy(subs, session.subs)
		session.subs = nil
		session.mu.Unlock()
		sendProgress(session.progress, subs)

		for _, ch := range subs {
			close(ch)
		}

		// Run download tests if requested
		if req.DownloadTop > 0 && len(session.result) > 0 {
			session.mu.Lock()
			session.status = "downloading"
			session.mu.Unlock()

			dlTop := req.DownloadTop
			if dlTop > len(session.result) {
				dlTop = len(session.result)
			}

			dlCfg := probe.DownloadConfig{
				Timeout: 45 * time.Second,
				Bytes:   50_000_000,
			}

			dlp := probe.NewDownloadProber(dlCfg)
			maxTests := dlTop
			if req.DownloadMode == "sequential" {
				maxTests = len(session.result)
			}

			successCount := 0
			for i := 0; i < maxTests && successCount < dlTop; i++ {
				r := &session.result[i]
				dctx, dcancel := context.WithTimeout(ctx, 45*time.Second)
				dr := dlp.Download(dctx, r.IP)
				dcancel()
				r.DownloadOK = dr.OK
				r.DownloadBytes = dr.Bytes
				r.DownloadMS = dr.TotalMS
				r.DownloadMbps = dr.Mbps
				r.DownloadError = dr.Error
				if dr.OK {
					successCount++
				}
				if req.DownloadMode == "sequential" && successCount >= dlTop {
					break
				}
			}
		}

		session.mu.Lock()
		session.status = "completed"
		session.mu.Unlock()
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
	resp, err := client.Get("http://ip-api.com/json/")
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
			info.ISP = ipData.ISP
			if ipData.Org != "" && ipData.Org != ipData.ISP {
				info.ISP = ipData.Org
			}
			info.Location = ipData.City + ", " + ipData.Region + ", " + ipData.Country
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
	json.NewEncoder(w).Encode(info)
}

type TracerouteHop struct {
	Hop  int    `json:"hop"`
	IP   string `json:"ip"`
	MS   string `json:"ms"`
	Lost bool   `json:"lost"`
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(hops)
}

func runTraceroute(ctx context.Context, ip string) []TracerouteHop {
	// Try traceroute first, fall back to tcptraceroute
	cmd := exec.CommandContext(ctx, "traceroute", "-n", "-q", "1", "-w", "2", ip)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil
	}
	if err := cmd.Start(); err != nil {
		return nil
	}

	var hops []TracerouteHop
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
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