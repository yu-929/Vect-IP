package server

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

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
		inlinePath := filepath.Join("/tmp/cfnb", "inline_"+id+".txt")
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

		scriptDir := "/tmp/cfnb"
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

		sendCfnbProgress(session, ProgressData{Stage: 1, Nodes: 0, Completed: 0, Budget: 100})

		pctx, pcancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer pcancel()

		cmd := exec.CommandContext(pctx, "python3", "main.py")
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