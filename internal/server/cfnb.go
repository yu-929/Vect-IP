package server

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yu-929/Vect-IP/internal/probe"
)

type CfnbSession struct {
	mu         sync.RWMutex
	status     string
	progress   ProgressData
	result     []map[string]interface{}
	output     string
	err        string
	ctx        context.Context
	cancel     context.CancelFunc
	subs       []chan ProgressData
	finishedAt time.Time
}

var (
	cfnbScans       = make(map[string]*CfnbSession)
	cfnbScansMu     sync.RWMutex
	cfnbIDCounter   int64
	cfnbServerPort  string
)

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

func SetCfnbServerPort(port string) {
	cfnbServerPort = port
}

func registerCfnbRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/cfnb/run", handleCfnbRun)
	mux.HandleFunc("/api/cfnb/run/", func(w http.ResponseWriter, r *http.Request) {
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

	mux.HandleFunc("/api/cfnb/cancel/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/cfnb/cancel/")
		handleCfnbCancel(w, id)
	})

	mux.HandleFunc("/api/cfnb/inline-sources/", func(w http.ResponseWriter, r *http.Request) {
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
	ctx, cancel := context.WithCancel(context.Background())

	session := &CfnbSession{
		status: "running",
		ctx:    ctx,
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
		scriptPath := filepath.Join(scriptDir, "main.py")
		usePython := pythonBin != ""
		if usePython {
			if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
				usePython = false
			}
		}

		if !usePython {
			runCfnbScanGo(session, req, id)
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
	lastProgress := session.progress
	session.mu.Unlock()

	if lastProgress.Stage > 0 {
		eventData, _ := json.Marshal(lastProgress)
		fmt.Fprintf(w, "data: %s\n\n", eventData)
		flusher.Flush()
	}

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
		case p, ok := <-ch:
			if !ok {
				fmt.Fprintf(w, "event: done\ndata: \n\n")
				flusher.Flush()
				return
			}
			eventData, _ := json.Marshal(p)
			fmt.Fprintf(w, "data: %s\n\n", eventData)
			flusher.Flush()
		}
	}
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

func intMax(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// --- Go-based CFNB scan engine (no Python dependency) ---

func selectPerCountry(results []cfnbIPResult, perCountryTopN int, globalTopN int) []cfnbIPResult {
	if perCountryTopN <= 0 {
		perCountryTopN = 1
	}
	groups := make(map[string][]cfnbIPResult)
	for _, r := range results {
		loc := ""
		if r.colo != "" {
			parts := strings.Split(r.colo, "-")
			if len(parts) >= 2 {
				loc = parts[len(parts)-1]
			}
		}
		if loc == "" {
			loc = "__unknown"
		}
		groups[loc] = append(groups[loc], r)
	}
	var selected []cfnbIPResult
	for _, group := range groups {
		sort.Slice(group, func(i, j int) bool {
			return group[i].score > group[j].score
		})
		n := perCountryTopN
		if n > len(group) {
			n = len(group)
		}
		selected = append(selected, group[:n]...)
	}
	sort.Slice(selected, func(i, j int) bool {
		return selected[i].score > selected[j].score
	})
	if len(selected) > globalTopN {
		selected = selected[:globalTopN]
	}
	return selected
}

func filterByCountry(results []cfnbIPResult, req cfnbRunRequest) []cfnbIPResult {
	if !req.WhitelistEnabled && !req.BlockedEnabled {
		return results
	}
	filtered := make([]cfnbIPResult, 0, len(results))
	for _, r := range results {
		loc := ""
		if r.colo != "" {
			parts := strings.Split(r.colo, "-")
			if len(parts) >= 2 {
				loc = parts[len(parts)-1]
			}
		}
		if loc == "" {
			filtered = append(filtered, r)
			continue
		}
		matched := true
		if req.WhitelistEnabled && len(req.WhitelistCountries) > 0 {
			matched = false
			for _, c := range req.WhitelistCountries {
				if strings.EqualFold(c, loc) {
					matched = true
					break
				}
			}
		}
		if matched && req.BlockedEnabled && len(req.BlockedCountries) > 0 {
			for _, c := range req.BlockedCountries {
				if strings.EqualFold(c, loc) {
					matched = false
					break
				}
			}
		}
		if matched {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

func runCfnbScanGo(session *CfnbSession, req cfnbRunRequest, id string) {
	scriptDir := filepath.Join(os.TempDir(), "cfnb")
	os.MkdirAll(scriptDir, 0755)

	sendCfnbProgress(session, ProgressData{Stage: 1, Nodes: 0, Completed: 0, Budget: 100})

	ips := collectCfnbIPs(req, id, session)
	if ips == nil {
		return
	}

	sendCfnbProgress(session, ProgressData{Stage: 1, Nodes: len(ips), Completed: 100, Budget: 100})

	timeout := time.Duration(req.TcpTimeout * float64(time.Second))
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	tcpProbes := intMax(1, req.TcpProbes)

	if req.PortFilterEnabled && len(req.Ports) > 0 {
		filtered := make([]cfnbIPEntry, 0, len(ips))
		portSet := make(map[int]bool)
		for _, p := range req.Ports {
			portSet[p] = true
		}
		for _, e := range ips {
			if portSet[e.port] {
				filtered = append(filtered, e)
			}
		}
		ips = filtered
	}

	total := len(ips)
	allResults := make([]cfnbIPResult, 0, total)
	resultMu := sync.Mutex{}
	workCh := make(chan int, total)
	workers := intMax(1, req.Workers)
	if workers > total {
		workers = total
	}
	var wg sync.WaitGroup

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range workCh {
				select {
				case <-session.ctx.Done():
					return
				default:
				}
				entry := ips[idx]
				var bestLatency float64
				successCount := 0
				for r := 0; r < tcpProbes; r++ {
					select {
					case <-session.ctx.Done():
						return
					default:
					}
					addr := net.JoinHostPort(entry.ip, strconv.Itoa(entry.port))
					start := time.Now()
					conn, err := net.DialTimeout("tcp", addr, timeout)
					if err != nil {
						continue
					}
					latency := time.Since(start).Seconds() * 1000
					conn.Close()
					successCount++
					if bestLatency == 0 || latency < bestLatency {
						bestLatency = latency
					}
				}
				r := cfnbIPResult{
					ip:   entry.ip,
					port: entry.port,
				}
				successRate := float64(successCount) / float64(tcpProbes)
				if successRate >= req.MinSuccessRate && successCount > 0 {
					r.ok = true
					r.tcpLatencyMS = bestLatency
				}
				resultMu.Lock()
				allResults = append(allResults, r)
				completed := len(allResults)
				pct := completed * 100 / total
				sendCfnbProgress(session, ProgressData{Stage: 2, Nodes: total, Completed: pct, Budget: 100})
				resultMu.Unlock()
			}
		}()
	}

	for i := 0; i < total; i++ {
		workCh <- i
	}
	close(workCh)
	wg.Wait()

	okResults := make([]cfnbIPResult, 0, len(allResults))
	for _, r := range allResults {
		if r.ok {
			okResults = append(okResults, r)
		}
	}

	if len(okResults) == 0 {
		session.mu.Lock()
		session.err = "no reachable IPs found"
		session.status = "failed"
		session.mu.Unlock()
		return
	}

	topN := req.TopN
	if topN <= 0 {
		topN = 20
	}
	if topN > len(okResults) {
		topN = len(okResults)
	}

	maxTcpLat := 1.0
	for _, r := range okResults {
		if r.tcpLatencyMS > maxTcpLat {
			maxTcpLat = r.tcpLatencyMS
		}
	}
	for i := range okResults {
		tcpScore := 0.0
		if maxTcpLat > 0 {
			tcpScore = (1 - okResults[i].tcpLatencyMS/maxTcpLat) * req.TcpLatWeight
		}
		okResults[i].score = tcpScore
	}
	sort.Slice(okResults, func(i, j int) bool {
		return okResults[i].score > okResults[j].score
	})

	// Keep all reachable IPs for availability/HTTP tests (don't filter by TCP latency)

	if req.TestAvailability {
		sendCfnbProgress(session, ProgressData{Stage: 3, Nodes: len(okResults), Completed: 0, Budget: len(okResults)})
		availCfg := probe.Config{
			Timeout:    3 * time.Second,
			SNI:        "api.090227.xyz",
			HostHeader: "api.090227.xyz",
			Path:       "/check",
			Port:       443,
			Rounds:     1,
			SkipFirst:  0,
		}
		ap := probe.NewProber(availCfg)
		var avWg sync.WaitGroup
		var avMu sync.Mutex
		avDone := 0
		avCh := make(chan int, len(okResults))
		avWorkers := intMax(1, req.Workers)
		if avWorkers > len(okResults) {
			avWorkers = len(okResults)
		}
		availResults := make([]cfnbIPResult, 0, len(okResults))
		var availMu sync.Mutex
		for w := 0; w < avWorkers; w++ {
			avWg.Add(1)
			go func() {
				defer avWg.Done()
				for idx := range avCh {
					select {
					case <-session.ctx.Done():
						return
					default:
					}
					r := &okResults[idx]
					addr, err := netip.ParseAddr(r.ip)
					if err != nil {
						continue
					}
					probeCtx, probeCancel := context.WithTimeout(context.Background(), availCfg.Timeout)
					res := ap.ProbeHTTPTrace(probeCtx, addr)
					probeCancel()
					avMu.Lock()
					avDone++
					sendCfnbProgress(session, ProgressData{Stage: 3, Nodes: len(okResults), Completed: avDone, Budget: len(okResults)})
					avMu.Unlock()
					if res.OK {
						loc := res.Trace["loc"]
						if loc != "" {
							r.colo = alpha2ToAlpha3(loc) + "-" + loc
						}
						availMu.Lock()
						availResults = append(availResults, *r)
						availMu.Unlock()
					}
				}
			}()
		}
		for i := 0; i < len(okResults); i++ {
			avCh <- i
		}
		close(avCh)
		avWg.Wait()
		if len(availResults) > 0 {
			okResults = availResults
		}
		if !req.GlobalMode {
			okResults = selectPerCountry(okResults, req.PerCountryTopN, topN)
		}
		okResults = filterByCountry(okResults, req)
		if len(okResults) == 0 {
			session.mu.Lock()
			session.err = "no reachable IPs after country filter"
			session.status = "failed"
			session.mu.Unlock()
			return
		}
		sendCfnbProgress(session, ProgressData{Stage: 3, Nodes: len(okResults), Completed: 100, Budget: 100})
	}

	sendCfnbProgress(session, ProgressData{Stage: 4, Nodes: len(okResults), Completed: 0, Budget: len(okResults)})

	if req.TestHttp && req.JitterSamples > 1 {
		httpCfg := probe.Config{
			Timeout:          3 * time.Second,
			SNI:              "example.com",
			HostHeader:       "example.com",
			Path:             "/cdn-cgi/trace",
			Port:             443,
			Rounds:           req.JitterSamples,
			SkipFailedRounds: true,
		}
		hp := probe.NewProber(httpCfg)

		var htWg sync.WaitGroup
		var htMu sync.Mutex
		htDone := 0
		htCh := make(chan int, len(okResults))
		htWorkers := intMax(1, req.Workers)
		if htWorkers > len(okResults) {
			htWorkers = len(okResults)
		}

		for w := 0; w < htWorkers; w++ {
			htWg.Add(1)
			go func() {
				defer htWg.Done()
				for idx := range htCh {
					select {
					case <-session.ctx.Done():
						return
					default:
					}
					r := &okResults[idx]
					addr, err := netip.ParseAddr(r.ip)
					if err != nil {
						continue
					}
					probeTimeout := httpCfg.Timeout * time.Duration(req.JitterSamples)
					if probeTimeout < 15*time.Second {
						probeTimeout = 15 * time.Second
					}
					probeCtx, probeCancel := context.WithTimeout(context.Background(), probeTimeout)
					res := hp.ProbeHTTPTraceMulti(probeCtx, addr)
					probeCancel()
					if res.OK {
						loc := res.Trace["loc"]
						if loc != "" {
							r.colo = alpha2ToAlpha3(loc) + "-" + loc
						}
						r.httpLatency = float64(res.TotalMS)
						r.jitterMS = float64(res.JitterMS)
					}
					htMu.Lock()
					htDone++
					sendCfnbProgress(session, ProgressData{Stage: 4, Nodes: len(okResults), Completed: htDone, Budget: len(okResults)})
					htMu.Unlock()
				}
			}()
		}
		for i := 0; i < len(okResults); i++ {
			htCh <- i
		}
		close(htCh)
		htWg.Wait()

		maxHttpLat := 1.0
		maxJitter := 1.0
		for _, r := range okResults {
			if r.httpLatency > maxHttpLat {
				maxHttpLat = r.httpLatency
			}
			if r.jitterMS > maxJitter {
				maxJitter = r.jitterMS
			}
		}
		for i := range okResults {
			httpScore := 0.0
			jitterScore := 0.0
			if maxHttpLat > 0 {
				httpScore = (1 - okResults[i].httpLatency/maxHttpLat) * req.HttpLatWeight
			}
			if maxJitter > 0 {
				jitterScore = (1 - okResults[i].jitterMS/maxJitter) * req.JitterWeight
			}
			tcpScore := 0.0
			if maxTcpLat > 0 {
				tcpScore = (1 - okResults[i].tcpLatencyMS/maxTcpLat) * req.TcpLatWeight
			}
			okResults[i].score = tcpScore + httpScore + jitterScore
		}
		sort.Slice(okResults, func(i, j int) bool {
			return okResults[i].score > okResults[j].score
		})
	}

	sendCfnbProgress(session, ProgressData{Stage: 4, Nodes: len(okResults), Completed: 100, Budget: 100})

	if !req.TestAvailability {
		okResults = filterByCountry(okResults, req)
		if len(okResults) == 0 {
			session.mu.Lock()
			session.err = "no reachable IPs after country filter"
			session.status = "failed"
			session.mu.Unlock()
			return
		}
	}

	if req.BwCandidates > 0 {
		bwCount := req.BwCandidates
		if bwCount > len(okResults) {
			bwCount = len(okResults)
		}

		dlCfg := probe.DownloadConfig{
			Timeout:  5 * time.Second,
			Bytes:    int64(req.BwSize * 1024 * 1024),
			SNI:      "speed.cloudflare.com",
			HostName: "speed.cloudflare.com",
		}
		if dlCfg.Bytes <= 0 {
			dlCfg.Bytes = 50_000_000
		}
		dlp := probe.NewDownloadProber(dlCfg)

		bwWorkers := intMax(1, req.BwWorkers)
		if bwWorkers > bwCount {
			bwWorkers = bwCount
		}
		bwCh := make(chan int, bwCount)
		var bwWg sync.WaitGroup
		var bwMu sync.Mutex
		bwDone := 0

		for w := 0; w < bwWorkers; w++ {
			bwWg.Add(1)
			go func() {
				defer bwWg.Done()
				for idx := range bwCh {
					select {
					case <-session.ctx.Done():
						return
					default:
					}
					r := &okResults[idx]
					addr, err := netip.ParseAddr(r.ip)
					if err != nil {
						continue
					}
					probeCtx, probeCancel := context.WithTimeout(context.Background(), 30*time.Second)
					dr := dlp.Download(probeCtx, addr)
					probeCancel()
					if dr.OK {
						r.speedMbps = dr.PeakMbps
					}
					bwMu.Lock()
					bwDone++
					sendCfnbProgress(session, ProgressData{Stage: 5, Nodes: bwCount, Completed: bwDone, Budget: bwCount})
					bwMu.Unlock()
				}
			}()
		}
		for i := 0; i < bwCount; i++ {
			bwCh <- i
		}
		close(bwCh)
		bwWg.Wait()

		okResults = okResults[:bwCount]

		maxSpeed := 1.0
		for _, r := range okResults {
			if r.speedMbps > maxSpeed {
				maxSpeed = r.speedMbps
			}
		}
		maxHttpLat2 := 1.0
		maxJitter2 := 1.0
		for _, r := range okResults {
			if r.httpLatency > maxHttpLat2 {
				maxHttpLat2 = r.httpLatency
			}
			if r.jitterMS > maxJitter2 {
				maxJitter2 = r.jitterMS
			}
		}
		for i := range okResults {
			tcpScore := 0.0
			httpScore := 0.0
			jitterScore := 0.0
			speedScore := 0.0
			if maxTcpLat > 0 {
				tcpScore = (1 - okResults[i].tcpLatencyMS/maxTcpLat) * req.TcpLatWeight
			}
			if maxHttpLat2 > 0 {
				httpScore = (1 - okResults[i].httpLatency/maxHttpLat2) * req.HttpLatWeight
			}
			if maxJitter2 > 0 {
				jitterScore = (1 - okResults[i].jitterMS/maxJitter2) * req.JitterWeight
			}
			if maxSpeed > 0 {
				speedScore = (okResults[i].speedMbps / maxSpeed) * req.SpeedWeight
			}
			okResults[i].score = tcpScore + httpScore + jitterScore + speedScore
		}
		sort.Slice(okResults, func(i, j int) bool {
			return okResults[i].score > okResults[j].score
		})
	}

	if req.GlobalMode {
		if topN > len(okResults) {
			topN = len(okResults)
		}
		okResults = okResults[:topN]
	}

	results := make([]map[string]interface{}, len(okResults))
	for i, r := range okResults {
		speedStr := ""
		httpLatStr := ""
		httpJitterStr := ""
		tcpLatStr := ""
		if r.speedMbps > 0 {
			speedStr = fmt.Sprintf("%.2f Mbps", r.speedMbps)
		} else {
			speedStr = "0.00 Mbps"
		}
		if r.httpLatency > 0 {
			httpLatStr = fmt.Sprintf("%.1f ms", r.httpLatency)
		} else {
			httpLatStr = "0 ms"
		}
		if r.jitterMS > 0 {
			httpJitterStr = fmt.Sprintf("%.1f ms", r.jitterMS)
		} else {
			httpJitterStr = "0 ms"
		}
		if r.tcpLatencyMS > 0 {
			tcpLatStr = fmt.Sprintf("%.1f ms", r.tcpLatencyMS)
		} else {
			tcpLatStr = "0 ms"
		}
		results[i] = map[string]interface{}{
			"ip":           r.ip,
			"port":         fmt.Sprintf("%d", r.port),
			"label":        r.colo,
			"speed":        speedStr,
			"http_latency": httpLatStr,
			"http_jitter":  httpJitterStr,
			"tcp_latency":  tcpLatStr,
		}
	}

	session.mu.Lock()
	session.result = results
	session.status = "completed"
	session.progress = ProgressData{Stage: 5, Completed: 100, Budget: 100}
	subs := make([]chan ProgressData, len(session.subs))
	copy(subs, session.subs)
	session.mu.Unlock()
	sendProgress(session.progress, subs)
}

func alpha2ToAlpha3(code string) string {
	m := map[string]string{
		"AF": "AFG", "AL": "ALB", "DZ": "DZA", "AS": "ASM", "AD": "AND", "AO": "AGO", "AI": "AIA",
		"AQ": "ATA", "AG": "ATG", "AR": "ARG", "AM": "ARM", "AW": "ABW", "AU": "AUS", "AT": "AUT",
		"AZ": "AZE", "BS": "BHS", "BH": "BHR", "BD": "BGD", "BB": "BRB", "BY": "BLR", "BE": "BEL",
		"BZ": "BLZ", "BJ": "BEN", "BM": "BMU", "BT": "BTN", "BO": "BOL", "BQ": "BES", "BA": "BIH",
		"BW": "BWA", "BV": "BVT", "BR": "BRA", "IO": "IOT", "BN": "BRN", "BG": "BGR", "BF": "BFA",
		"BI": "BDI", "CV": "CPV", "KH": "KHM", "CM": "CMR", "CA": "CAN", "KY": "CYM", "CF": "CAF",
		"TD": "TCD", "CL": "CHL", "CN": "CHN", "CX": "CXR", "CC": "CCK", "CO": "COL", "KM": "COM",
		"CD": "COD", "CG": "COG", "CK": "COK", "CR": "CRI", "HR": "HRV", "CU": "CUB", "CW": "CUW",
		"CY": "CYP", "CZ": "CZE", "CI": "CIV", "DK": "DNK", "DJ": "DJI", "DM": "DMA", "DO": "DOM",
		"EC": "ECU", "EG": "EGY", "SV": "SLV", "GQ": "GNQ", "ER": "ERI", "EE": "EST", "SZ": "SWZ",
		"ET": "ETH", "FK": "FLK", "FO": "FRO", "FJ": "FJI", "FI": "FIN", "FR": "FRA", "GF": "GUF",
		"PF": "PYF", "TF": "ATF", "GA": "GAB", "GM": "GMB", "GE": "GEO", "DE": "DEU", "GH": "GHA",
		"GI": "GIB", "GR": "GRC", "GL": "GRL", "GD": "GRD", "GP": "GLP", "GU": "GUM", "GT": "GTM",
		"GG": "GGY", "GN": "GIN", "GW": "GNB", "GY": "GUY", "HT": "HTI", "HM": "HMD", "VA": "VAT",
		"HN": "HND", "HK": "HKG", "HU": "HUN", "IS": "ISL", "IN": "IND", "ID": "IDN", "IR": "IRN",
		"IQ": "IRQ", "IE": "IRL", "IM": "IMN", "IL": "ISR", "IT": "ITA", "JM": "JAM", "JP": "JPN",
		"JE": "JEY", "JO": "JOR", "KZ": "KAZ", "KE": "KEN", "KI": "KIR", "KP": "PRK", "KR": "KOR",
		"KW": "KWT", "KG": "KGZ", "LA": "LAO", "LV": "LVA", "LB": "LBN", "LS": "LSO", "LR": "LBR",
		"LY": "LBY", "LI": "LIE", "LT": "LTU", "LU": "LUX", "MO": "MAC", "MG": "MDG", "MW": "MWI",
		"MY": "MYS", "MV": "MDV", "ML": "MLI", "MT": "MLT", "MH": "MHL", "MQ": "MTQ", "MR": "MRT",
		"MU": "MUS", "YT": "MYT", "MX": "MEX", "FM": "FSM", "MD": "MDA", "MC": "MCO", "MN": "MNG",
		"ME": "MNE", "MS": "MSR", "MA": "MAR", "MZ": "MOZ", "MM": "MMR", "NA": "NAM", "NR": "NRU",
		"NP": "NPL", "NL": "NLD", "NC": "NCL", "NZ": "NZL", "NI": "NIC", "NE": "NER", "NG": "NGA",
		"NU": "NIU", "NF": "NFK", "MK": "MKD", "MP": "MNP", "NO": "NOR", "OM": "OMN", "PK": "PAK",
		"PW": "PLW", "PS": "PSE", "PA": "PAN", "PG": "PNG", "PY": "PRY", "PE": "PER", "PH": "PHL",
		"PN": "PCN", "PL": "POL", "PT": "PRT", "PR": "PRI", "QA": "QAT", "RE": "REU", "RO": "ROU",
		"RU": "RUS", "RW": "RWA", "BL": "BLM", "SH": "SHN", "KN": "KNA", "LC": "LCA", "MF": "MAF",
		"PM": "SPM", "VC": "VCT", "WS": "WSM", "SM": "SMR", "ST": "STP", "SA": "SAU", "SN": "SEN",
		"RS": "SRB", "SC": "SYC", "SL": "SLE", "SG": "SGP", "SX": "SXM", "SK": "SVK", "SI": "SVN",
		"SB": "SLB", "SO": "SOM", "ZA": "ZAF", "GS": "SGS", "SS": "SSD", "ES": "ESP", "LK": "LKA",
		"SD": "SDN", "SR": "SUR", "SJ": "SJM", "SE": "SWE", "CH": "CHE", "SY": "SYR", "TW": "TWN",
		"TJ": "TJK", "TZ": "TZA", "TH": "THA", "TL": "TLS", "TG": "TGO", "TK": "TKL", "TO": "TON",
		"TT": "TTO", "TN": "TUN", "TR": "TUR", "TM": "TKM", "TC": "TCA", "TV": "TUV", "UG": "UGA",
		"UA": "UKR", "AE": "ARE", "GB": "GBR", "UM": "UMI", "US": "USA", "UY": "URY", "UZ": "UZB",
		"VU": "VUT", "VE": "VEN", "VN": "VNM", "VG": "VGB", "VI": "VIR", "WF": "WLF", "EH": "ESH",
		"YE": "YEM", "ZM": "ZMB", "ZW": "ZWE",
	}
	if v, ok := m[code]; ok {
		return v
	}
	return code
}

type cfnbIPResult struct {
	ip           string
	port         int
	colo         string
	jitterMS     float64
	tcpLatencyMS float64
	httpLatency  float64
	speedMbps    float64
	ok           bool
	score        float64
}

type cfnbIPEntry struct {
	ip   string
	port int
}

func collectCfnbIPs(req cfnbRunRequest, id string, session *CfnbSession) []cfnbIPEntry {
	seen := map[string]bool{}
	var entries []cfnbIPEntry

	addIP := func(ip string, port int) {
		key := fmt.Sprintf("%s:%d", ip, port)
		if seen[key] {
			return
		}
		seen[key] = true
		entries = append(entries, cfnbIPEntry{ip: ip, port: port})
	}

	for _, source := range req.Sources {
		ips := fetchURLIPs(source, session)
		if ips == nil {
			return nil
		}
		for _, entry := range ips {
			addIP(entry.ip, entry.port)
		}
	}

	for _, cidr := range req.CIDRs {
		expanded, err := expandCIDR(cidr)
		if err != nil {
			session.mu.Lock()
			session.err = "expand CIDR " + cidr + ": " + err.Error()
			session.status = "failed"
			session.mu.Unlock()
			return nil
		}
		for _, ip := range expanded {
			addIP(ip, 443)
		}
	}

	for _, ip := range req.IPs {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		if strings.Contains(ip, ":") {
			parts := strings.SplitN(ip, ":", 2)
			port := 443
			if p, err := strconv.Atoi(parts[1]); err == nil {
				port = p
			}
			addIP(parts[0], port)
		} else {
			addIP(ip, 443)
		}
	}

	return entries
}

func fetchURLIPs(url string, session *CfnbSession) []cfnbIPEntry {
	var lastErr error
	for retry := 0; retry < 3; retry++ {
		if retry > 0 {
			time.Sleep(time.Duration(retry) * time.Second)
		}
		client := &http.Client{Timeout: 15 * time.Second}
		resp, err := client.Get(url)
		if err != nil {
			lastErr = err
			continue
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
		if err != nil {
			lastErr = err
			continue
		}

		lines := strings.Split(string(body), "\n")
		var entries []cfnbIPEntry
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
				continue
			}
			ipport := strings.SplitN(line, "#", 2)[0]
			ipport = strings.TrimSpace(ipport)
			if ipport == "" {
				continue
			}
			ip := ipport
			port := 443
			if strings.Contains(ipport, ":") {
				parts := strings.SplitN(ipport, ":", 2)
				ip = parts[0]
				if p, err := strconv.Atoi(parts[1]); err == nil {
					port = p
				}
			}
			if net.ParseIP(ip) != nil {
				entries = append(entries, cfnbIPEntry{ip: ip, port: port})
			}
		}
		return entries
	}
	session.mu.Lock()
	session.err = "fetch source " + url + ": " + lastErr.Error()
	session.status = "failed"
	session.mu.Unlock()
	return nil
}