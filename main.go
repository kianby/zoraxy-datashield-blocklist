package main

import (
	"bufio"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	plugin "github.com/yax/zoraxy-datashield-blocklist/mod/zoraxy_plugin"
)

//go:embed ui
var uiFiles embed.FS

const (
	pluginID        = "fr.madyanne.zoraxy.datashield-blocklist"
	blocklistURL    = "https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv4_Blocklist/refs/heads/main/prod_data-shield_ipv4_blocklist.txt"
	refreshInterval = 6 * time.Hour
	minValidIPs     = 1000
)

var (
	blocklist   map[string]struct{}
	blocklistMu sync.RWMutex
	lastUpdated time.Time

	manualBlocklist   = map[string]struct{}{}
	manualBlocklistMu sync.RWMutex

	blockedCount atomic.Int64
	ipCount      atomic.Int64

	privateNets []*net.IPNet
)

func init() {
	for _, cidr := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"100.64.0.0/10",
	} {
		_, network, _ := net.ParseCIDR(cidr)
		privateNets = append(privateNets, network)
	}
	blocklist = make(map[string]struct{})
}

var pluginSpec = plugin.IntroSpect{
	ID:            pluginID,
	Name:          "Data-Shield Blocklist",
	Author:        "Yax",
	AuthorContact: "",
	Description:   "Blocks incoming connections from IPs listed in the Data-Shield IPv4 Blocklist (~100k IPs, updated every 6h).",
	URL:           "https://github.com/kianby/zoraxy-datashield-blocklist",
	Type:          plugin.PluginType_Router,
	VersionMajor:  1,
	VersionMinor:  3,
	VersionPatch:  0,
	DynamicCaptureSniff:   "/sniff",
	DynamicCaptureIngress: "/block",
	UIPath:                "/ui",
}

func main() {
	configSpec, err := plugin.ServeAndRecvSpec(&pluginSpec)
	if err != nil {
		log.Fatal("[datashield] Failed to receive configure spec:", err)
	}

	if err := refreshBlocklist(); err != nil {
		log.Printf("[datashield] Warning: initial blocklist load failed: %v — the blocklist is EMPTY and the plugin is blocking nothing until a refresh succeeds", err)
	}

	go func() {
		ticker := time.NewTicker(refreshInterval)
		defer ticker.Stop()
		for range ticker.C {
			if err := refreshBlocklist(); err != nil {
				log.Printf("[datashield] Blocklist refresh failed: %v", err)
			}
		}
	}()

	mux := http.NewServeMux()
	router := plugin.NewPathRouter()

	router.RegisterDynamicSniffHandler("/sniff", mux, sniffHandler)
	router.RegisterDynamicCaptureHandle("/block", mux, blockHandler)

	uiRouter := plugin.NewPluginEmbedUIRouter(pluginID, &uiFiles, "/ui", "/ui")
	uiRouter.RegisterTerminateHandler(func() {
		log.Println("[datashield] Plugin terminated by Zoraxy")
	}, mux)
	uiRouter.HandleFunc("/api/status", statusHandler, mux)
	uiRouter.HandleFunc("/api/refresh", refreshHandler, mux)
	uiRouter.HandleFunc("/api/add-ip", addIPHandler, mux)
	uiRouter.HandleFunc("/api/remove-ip", removeIPHandler, mux)
	uiRouter.AttachHandlerToMux(mux)

	addr := fmt.Sprintf("127.0.0.1:%d", configSpec.Port)
	log.Printf("[datashield] Plugin listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// sniffHandler is called by Zoraxy for every incoming request.
// It returns SniffResultAccept to block the IP, or SniffResultSkip to let it through.
func sniffHandler(req *plugin.DynamicSniffForwardRequest) plugin.SniffResult {
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return plugin.SniffResultSkip
	}

	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		// Skip IPv6 — the Data-Shield list is IPv4 only
		return plugin.SniffResultSkip
	}

	for _, network := range privateNets {
		if network.Contains(parsed) {
			return plugin.SniffResultSkip
		}
	}

	blocklistMu.RLock()
	_, blocked := blocklist[ip]
	blocklistMu.RUnlock()

	if !blocked {
		manualBlocklistMu.RLock()
		_, blocked = manualBlocklist[ip]
		manualBlocklistMu.RUnlock()
	}

	if blocked {
		return plugin.SniffResultAccept
	}
	return plugin.SniffResultSkip
}

// blockHandler is called by Zoraxy when sniffHandler returns SniffResultAccept.
// It returns a 403 Forbidden response to the client.
func blockHandler(w http.ResponseWriter, r *http.Request) {
	blockedCount.Add(1)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprint(w, `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>403 Forbidden</title>
  <style>
    body { font-family: sans-serif; max-width: 600px; margin: 4rem auto; text-align: center; }
    h1 { color: #c0392b; }
    p { color: #555; margin-top: 1rem; }
  </style>
</head>
<body>
  <h1>403 Forbidden</h1>
  <p>Your IP address has been identified as a threat by the Data-Shield security filter and access has been denied.</p>
</body>
</html>`)
}

// refreshBlocklist downloads the Data-Shield IPv4 Blocklist and replaces the in-memory map.
// On failure, the existing blocklist is kept unchanged.
func refreshBlocklist() error {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(blocklistURL)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}

	newList, err := parseBlocklist(resp.Body)
	if err != nil {
		return err
	}

	blocklistMu.Lock()
	blocklist = newList
	lastUpdated = time.Now()
	blocklistMu.Unlock()

	ipCount.Store(int64(len(newList)))
	log.Printf("[datashield] Blocklist updated: %d IPs loaded", len(newList))
	return nil
}

// parseBlocklist reads one IPv4 address per line, skipping blanks, comments and invalid lines.
// It fails if fewer than minValidIPs valid addresses are found, so a bad download never replaces a good list.
func parseBlocklist(r io.Reader) (map[string]struct{}, error) {
	// Pre-allocate with a capacity slightly above the expected ~100k entries
	list := make(map[string]struct{}, 110000)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parsed := net.ParseIP(line)
		if parsed == nil || parsed.To4() == nil {
			continue
		}
		list[parsed.String()] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if len(list) < minValidIPs {
		return nil, fmt.Errorf("only %d valid IPs found (need at least %d), keeping existing list", len(list), minValidIPs)
	}
	return list, nil
}

type statusResponse struct {
	Loaded       bool      `json:"loaded"`
	IPCount      int64     `json:"ip_count"`
	LastUpdated  time.Time `json:"last_updated"`
	BlockedCount int64     `json:"blocked_count"`
	ManualIPs    []string  `json:"manual_ips"`
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	blocklistMu.RLock()
	loaded := len(blocklist) > 0
	upd := lastUpdated
	blocklistMu.RUnlock()

	manualBlocklistMu.RLock()
	manualIPs := make([]string, 0, len(manualBlocklist))
	for ip := range manualBlocklist {
		manualIPs = append(manualIPs, ip)
	}
	manualBlocklistMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(statusResponse{
		Loaded:       loaded,
		IPCount:      ipCount.Load(),
		LastUpdated:  upd,
		BlockedCount: blockedCount.Load(),
		ManualIPs:    manualIPs,
	})
}

func addIPHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	rawIP := r.URL.Query().Get("ip")
	if rawIP == "" {
		http.Error(w, "Bad Request: missing ip parameter", http.StatusBadRequest)
		return
	}
	parsed := net.ParseIP(rawIP)
	if parsed == nil || parsed.To4() == nil {
		http.Error(w, "Bad Request: must be a valid IPv4 address", http.StatusBadRequest)
		return
	}
	ip := parsed.String()
	manualBlocklistMu.Lock()
	manualBlocklist[ip] = struct{}{}
	manualBlocklistMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "added", "ip": ip})
}

func removeIPHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	rawIP := r.URL.Query().Get("ip")
	if rawIP == "" {
		http.Error(w, "Bad Request: missing ip parameter", http.StatusBadRequest)
		return
	}
	parsed := net.ParseIP(rawIP)
	if parsed == nil {
		http.Error(w, "Bad Request: invalid IP address", http.StatusBadRequest)
		return
	}
	ip := parsed.String()
	manualBlocklistMu.Lock()
	delete(manualBlocklist, ip)
	manualBlocklistMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "removed", "ip": ip})
}

func refreshHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	go func() {
		if err := refreshBlocklist(); err != nil {
			log.Printf("[datashield] Manual refresh failed: %v", err)
		}
	}()
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"refresh_started"}`))
}
