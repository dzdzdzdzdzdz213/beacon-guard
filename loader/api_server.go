package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
)

type APIServer struct {
	engine  *Engine
	config  *Config
	alerts  []map[string]interface{}
	mu      sync.RWMutex
	clients map[chan string]bool
}

func NewAPIServer(engine *Engine, config *Config) *APIServer {
	return &APIServer{
		engine:  engine,
		config:  config,
		alerts:  make([]map[string]interface{}, 0, 10000),
		clients: make(map[chan string]bool),
	}
}

func (s *APIServer) startAlertConsumer() {
	go func() {
		for alert := range alertChan {
			s.AddAlert(alert)
		}
	}()
}

func (s *APIServer) Start(port int) {
	mux := http.NewServeMux()

	// Wrap with CORS
	handler := corsMiddleware(mux)

	mux.HandleFunc("/api/v1/health", s.handleHealth)
	mux.HandleFunc("/api/v1/stats", s.handleStats)
	mux.HandleFunc("/api/v1/processes", s.handleProcesses)
	mux.HandleFunc("/api/v1/alerts", s.handleAlerts)
	mux.HandleFunc("/api/v1/config", s.handleConfig)
	mux.HandleFunc("/api/v1/alerts/stream", s.handleSSE)

	addr := fmt.Sprintf(":%d", port)
	log.Printf("API server listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, handler))
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *APIServer) AddAlert(alert map[string]interface{}) {
	s.mu.Lock()
	s.alerts = append(s.alerts, alert)
	if len(s.alerts) > 10000 {
		s.alerts = s.alerts[len(s.alerts)-5000:]
	}
	clients := make([]chan string, 0, len(s.clients))
	for c := range s.clients {
		clients = append(clients, c)
	}
	s.mu.Unlock()

	data, _ := json.Marshal(alert)
	msg := fmt.Sprintf("data: %s\n\n", string(data))
	for _, c := range clients {
		select {
		case c <- msg:
		default:
		}
	}
}

func (s *APIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"version": "0.1.0",
	})
}

func (s *APIServer) handleStats(w http.ResponseWriter, r *http.Request) {
	eng := s.engine.GetStats()
	severityCounts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

	s.mu.RLock()
	for _, a := range s.alerts {
		sev, _ := a["severity"].(string)
		severityCounts[sev]++
	}
	alertCount := len(s.alerts)
	s.mu.RUnlock()

	withAlerts := 0
	for _, p := range s.engine.GetProfiles() {
		if len(p.Anomalies) > 0 {
			withAlerts++
		}
	}

	stats := map[string]interface{}{
		"alerts": map[string]interface{}{
			"total":        alertCount,
			"by_severity":  severityCounts,
			"last_hour":    alertCount,
		},
		"processes": map[string]interface{}{
			"total":       eng["total_processes"],
			"with_alerts": withAlerts,
		},
		"config": map[string]interface{}{
			"learning_mode": eng["learning_mode"],
		},
	}
	json.NewEncoder(w).Encode(stats)
}

func (s *APIServer) handleProcesses(w http.ResponseWriter, r *http.Request) {
	profiles := s.engine.GetProfiles()
	result := make([]map[string]interface{}, 0, len(profiles))

	for _, p := range profiles {
		result = append(result, map[string]interface{}{
			"pid":                p.Pid,
			"comm":               p.Comm,
			"first_seen":         p.FirstSeen,
			"last_seen":          p.LastSeen,
			"exec_count":         p.ExecCount,
			"network_conn_count": p.NetworkConnCount,
			"file_write_count":   p.FileWriteCount,
			"suspicion_score":    p.SuspicionScore,
			"state":              p.State,
			"anomaly_count":      len(p.Anomalies),
		})
	}

	json.NewEncoder(w).Encode(result)
}

func (s *APIServer) handleAlerts(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	limit := 100
	start := len(s.alerts) - limit
	if start < 0 {
		start = 0
	}

	json.NewEncoder(w).Encode(s.alerts[start:])
}

func (s *APIServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(s.config)
	case http.MethodPost:
		var newConfig Config
		if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		*s.config = newConfig
		json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
	}
}

func (s *APIServer) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan string, 100)
	s.mu.Lock()
	s.clients[ch] = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.clients, ch)
		s.mu.Unlock()
	}()

	for {
		select {
		case msg := <-ch:
			fmt.Fprintf(w, msg)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

var engine *Engine
