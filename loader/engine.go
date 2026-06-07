package main

import (
	"math"
	"sync"
	"time"
)

// Engine performs behavioral analysis on events
type Engine struct {
	config  *Config
	mu      sync.RWMutex

	// Per-process profiles
	profiles map[int]*ProcessProfile

	// Global baseline
	baseline *Baseline

	// Rule engine
	rules []Rule
}

type ProcessProfile struct {
	Pid             int
	Comm            string
	FirstSeen       time.Time
	LastSeen        time.Time
	ExecCount       int
	FileWriteCount  int
	NetworkConnCount int
	Connections     []ConnectionRecord
	FileWrites      []string
	Executables     []string
	SuspicionScore  int
	Anomalies       []Anomaly
	State           string // "learning", "baseline", "anomalous"
}

type ConnectionRecord struct {
	IP        string
	Port      int
	Timestamp time.Time
	Direction string
}

type Baseline struct {
	MaxExecPerMin         float64
	MaxFileWritePerMin    float64
	MaxConnPerMin         float64
	KnownParents          map[string]int
	KnownConnections      map[string]int
	TypicalFilePaths      map[string]int
	BuildTime             time.Time
	SampleCount           int
}

type Rule struct {
	Name        string
	Severity    string // "info", "low", "medium", "high", "critical"
	Score       int
	Description string
	Action      string // "alert", "block", "kill"
	Match       func(event *Event, profile *ProcessProfile, baseline *Baseline) *Anomaly
}

type Anomaly struct {
	Pid         int
	Comm        string
	Rule        string
	Severity    string
	Score       int
	Description string
	Action      string
	Details     map[string]interface{}
	Timestamp   time.Time
}

func NewEngine(config *Config) *Engine {
	e := &Engine{
		config:   config,
		profiles: make(map[int]*ProcessProfile),
		baseline: &Baseline{
			KnownParents:     make(map[string]int),
			KnownConnections: make(map[string]int),
			TypicalFilePaths: make(map[string]int),
			BuildTime:        time.Now(),
		},
	}

	e.registerBuiltinRules()
	return e
}

func (e *Engine) registerBuiltinRules() {
	e.rules = []Rule{
		// === EXECUTION ANOMALIES ===
		{
			Name: "unexpected_binary",
			Severity: "high",
			Score: 60,
			Description: "Process executed a binary not seen in baseline",
			Action: "alert",
			Match: func(evt *Event, p *ProcessProfile, bl *Baseline) *Anomaly {
				if evt.Type != 1 { return nil }
				filename, _ := evt.Data["filename"].(string)
				if filename == "" { return nil }
				if p.State != "baseline" { return nil }
				found := false
				for _, allowed := range bl.KnownParents {
					if filename == "" { continue }
					_ = allowed
				}
				// Check allowed list
				for _, allowed := range e.config.AllowedExecutables {
					if filename == allowed {
						found = true
						break
					}
				}
				if !found && p.ExecCount > 1 {
					return &Anomaly{
						Rule: "unexpected_binary",
						Severity: "high",
						Score: 60,
						Description: "Unexpected binary executed",
						Action: "alert",
						Details: map[string]interface{}{"filename": filename},
					}
				}
				return nil
			},
		},
		{
			Name: "process_running_as_root",
			Severity: "medium",
			Score: 40,
			Description: "Process running as root when not expected",
			Action: "alert",
			Match: func(evt *Event, p *ProcessProfile, bl *Baseline) *Anomaly {
				if evt.Type != 1 { return nil }
				if evt.Uid == 0 && p.ExecCount < 3 {
					return &Anomaly{
						Rule: "process_running_as_root",
						Severity: "medium",
						Score: 40,
						Description: "Process running as root",
						Action: "alert",
						Details: map[string]interface{}{"comm": evt.Comm},
					}
				}
				return nil
			},
		},

		// === NETWORK ANOMALIES ===
		{
			Name: "beaconing_detected",
			Severity: "critical",
			Score: 90,
			Description: "Process connecting to external IPs at regular intervals",
			Action: "kill",
			Match: func(evt *Event, p *ProcessProfile, bl *Baseline) *Anomaly {
				if evt.Type != 3 { return nil }
				if len(p.Connections) < 5 { return nil }

				// Check for periodic connections (beaconing)
				intervals := []float64{}
				for i := 1; i < len(p.Connections); i++ {
					intervals = append(intervals,
						p.Connections[i].Timestamp.Sub(p.Connections[i-1].Timestamp).Seconds())
				}

				if len(intervals) < 3 { return nil }

				// Calculate variance — low variance = periodic = beaconing
				mean := 0.0
				for _, iv := range intervals { mean += iv }
				mean /= float64(len(intervals))

				variance := 0.0
				for _, iv := range intervals { variance += (iv - mean) * (iv - mean) }
				variance /= float64(len(intervals))

				// Low variance (< 20% of mean) suggests beaconing
				if mean > 1 && variance < (mean*0.2) {
					return &Anomaly{
						Rule: "beaconing_detected",
						Severity: "critical",
						Score: 90,
						Description: "Periodic external connections detected",
						Action: "kill",
						Details: map[string]interface{}{
							"interval_mean": math.Round(mean*100)/100,
							"interval_var": math.Round(variance*100)/100,
							"connections": len(p.Connections),
						},
					}
				}
				return nil
			},
		},
		{
			Name: "reverse_shell_port",
			Severity: "critical",
			Score: 100,
			Description: "Connection to known reverse shell / C2 port",
			Action: "kill",
			Match: func(evt *Event, p *ProcessProfile, bl *Baseline) *Anomaly {
				if evt.Type != 3 { return nil }
				port, _ := evt.Data["port"].(int)
				ip, _ := evt.Data["ip"].(string)

				badPorts := map[int]string{
					4444: "Metasploit default",
					5555: "Android ADB / C2",
					6666: "IRC botnet",
					6667: "IRC / C2",
					7777: "C2 common",
					8443: "Alternative HTTPS C2",
					10000: "Webmin / C2",
					31337: "Back Orifice",
					4443: "C2 alternative HTTPS",
				}

				if reason, ok := badPorts[port]; ok {
					return &Anomaly{
						Rule: "reverse_shell_port",
						Severity: "critical",
						Score: 100,
						Description: "Connection to known C2 port",
						Action: "kill",
						Details: map[string]interface{}{
							"ip": ip,
							"port": port,
							"reason": reason,
						},
					}
				}
				return nil
			},
		},
		{
			Name: "dns_tunneling",
			Severity: "high",
			Score: 70,
			Description: "Large DNS queries indicating DNS tunneling",
			Action: "alert",
			Match: func(evt *Event, p *ProcessProfile, bl *Baseline) *Anomaly {
				if evt.Type != 3 { return nil }
				port, _ := evt.Data["port"].(int)
				if port != 53 { return nil }
				ret, _ := evt.Data["ret"].(int)
				if ret == 1 {
					return &Anomaly{
						Rule: "dns_tunneling",
						Severity: "high",
						Score: 70,
						Description: "Suspiciously large DNS query",
						Action: "alert",
						Details: map[string]interface{}{
							"pid": evt.Pid,
							"comm": evt.Comm,
						},
					}
				}
				return nil
			},
		},
		{
			Name: "rapid_succession_connections",
			Severity: "high",
			Score: 65,
			Description: "Rapid connections to multiple external IPs",
			Action: "alert",
			Match: func(evt *Event, p *ProcessProfile, bl *Baseline) *Anomaly {
				if evt.Type != 3 { return nil }
				if len(p.Connections) < 10 { return nil }

				window := 5.0 // seconds
				recent := 0
				now := time.Now()
				for i := len(p.Connections) - 1; i >= 0; i-- {
					if now.Sub(p.Connections[i].Timestamp).Seconds() < window {
						recent++
					} else {
						break
					}
				}

				if recent >= e.config.MaxConnectionsPerMin/12 {
					ips := []string{}
					for i := len(p.Connections) - recent; i < len(p.Connections); i++ {
						if p.Connections[i].IP != "" {
							ips = append(ips, p.Connections[i].IP)
						}
					}
					return &Anomaly{
						Rule: "rapid_succession_connections",
						Severity: "high",
						Score: 65,
						Description: "Rapid external connections",
						Action: "alert",
						Details: map[string]interface{}{
							"count": recent,
							"window_sec": window,
							"ips": ips,
						},
					}
				}
				return nil
			},
		},

		// === FILE SYSTEM ANOMALIES ===
		{
			Name: "mass_file_deletion",
			Severity: "critical",
			Score: 95,
			Description: "Rapid file deletions — possible ransomware",
			Action: "kill",
			Match: func(evt *Event, p *ProcessProfile, bl *Baseline) *Anomaly {
				if evt.Type != 2 { return nil }
				if evt.Ret != -2 { return nil }
				if p.FileWriteCount < 20 { return nil }

				return &Anomaly{
					Rule: "mass_file_deletion",
					Severity: "critical",
					Score: 95,
					Description: "Mass file deletions detected",
					Action: "kill",
					Details: map[string]interface{}{
						"deletions": p.FileWriteCount,
						"comm": evt.Comm,
					},
				}
			},
		},
		{
			Name: "sensitive_file_write",
			Severity: "critical",
			Score: 85,
			Description: "Write to sensitive system file",
			Action: "block",
			Match: func(evt *Event, p *ProcessProfile, bl *Baseline) *Anomaly {
				if evt.Type != 2 { return nil }
				filename, _ := evt.Data["filename"].(string)
				ret, _ := evt.Data["ret"].(int)
				if ret == -1 {
					return &Anomaly{
						Rule: "sensitive_file_write",
						Severity: "critical",
						Score: 85,
						Description: "Write to sensitive system path",
						Action: "block",
						Details: map[string]interface{}{
							"filename": filename,
							"comm": evt.Comm,
						},
					}
				}
				return nil
			},
		},

		// === MEMORY ANOMALIES ===
		{
			Name: "executable_mmap",
			Severity: "medium",
			Score: 30,
			Description: "Process mapped executable memory",
			Action: "alert",
			Match: func(evt *Event, p *ProcessProfile, bl *Baseline) *Anomaly {
				if evt.Type != 5 { return nil }
				return &Anomaly{
					Rule: "executable_mmap",
					Severity: "medium",
					Score: 30,
					Description: "Executable memory mapping",
					Action: "alert",
					Details: map[string]interface{}{
						"pid": evt.Pid,
						"comm": evt.Comm,
					},
				}
			},
		},

		// === PROCESS ANOMALIES ===
		{
			Name: "ptrace_attachment",
			Severity: "high",
			Score: 60,
			Description: "Process attached to non-child via ptrace",
			Action: "alert",
			Match: func(evt *Event, p *ProcessProfile, bl *Baseline) *Anomaly {
				if evt.Type != 8 { return nil }
				return &Anomaly{
					Rule: "ptrace_attachment",
					Severity: "high",
					Score: 60,
					Description: "Ptrace to non-child process",
					Action: "alert",
					Details: map[string]interface{}{
						"target_pid": evt.Ret,
						"source_pid": evt.Pid,
					},
				}
			},
		},
	}
}

func (e *Engine) Analyze(event *Event) *Anomaly {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Get or create process profile
	profile, exists := e.profiles[event.Pid]
	if !exists {
		profile = &ProcessProfile{
			Pid:       event.Pid,
			Comm:      event.Comm,
			FirstSeen: time.Now(),
			State:     "learning",
		}
		e.profiles[event.Pid] = profile
	}

	profile.LastSeen = time.Now()

	// Update profile based on event type
	switch event.Type {
	case 1: // EXECVE
		profile.ExecCount++
		if filename, ok := event.Data["filename"].(string); ok {
			profile.Executables = append(profile.Executables, filename)
		}
	case 2: // OPEN
		profile.FileWriteCount++
		if filename, ok := event.Data["filename"].(string); ok {
			profile.FileWrites = append(profile.FileWrites, filename)
		}
	case 3: // CONNECT
		profile.NetworkConnCount++
		ip, _ := event.Data["ip"].(string)
		port, _ := event.Data["port"].(int)
		if event.Ret == 1 {
			profile.SuspicionScore += 20
		}
		profile.Connections = append(profile.Connections, ConnectionRecord{
			IP: ip, Port: port,
			Timestamp: time.Now(),
			Direction: "outbound",
		})
	}

	// Learning mode: just observe
	if e.config.LearningMode {
		if time.Since(profile.FirstSeen).Seconds() > float64(e.config.BaselineWindowSec) {
			profile.State = "baseline"
		}
		return nil
	}

	// Enforcement mode: run rules
	profile.State = "baseline"

	for _, rule := range e.rules {
		anomaly := rule.Match(event, profile, e.baseline)
		if anomaly != nil {
			anomaly.Pid = event.Pid
			anomaly.Comm = event.Comm
			anomaly.Timestamp = time.Now()
			anomaly.Score = rule.Score

			// Aggregate suspicion score
			profile.SuspicionScore += anomaly.Score

			profile.Anomalies = append(profile.Anomalies, *anomaly)

			// Escalate action based on total score
			if profile.SuspicionScore >= e.config.SuspicionThreshold {
				anomaly.Action = "kill"
			}

			return anomaly
		}
	}

	return nil
}

func (e *Engine) GetProfiles() map[int]*ProcessProfile {
	e.mu.RLock()
	defer e.mu.RUnlock()

	profiles := make(map[int]*ProcessProfile)
	for k, v := range e.profiles {
		profiles[k] = v
	}
	return profiles
}

func (e *Engine) GetStats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	totalAnomalies := 0
	totalSuspicion := 0
	learningCount := 0
	baselineCount := 0
	anomalousCount := 0

	for _, p := range e.profiles {
		totalAnomalies += len(p.Anomalies)
		totalSuspicion += p.SuspicionScore
		switch p.State {
		case "learning": learningCount++
		case "baseline": baselineCount++
		case "anomalous": anomalousCount++
		}
	}

	return map[string]interface{}{
		"total_processes":   len(e.profiles),
		"total_anomalies":   totalAnomalies,
		"total_suspicion":   totalSuspicion,
		"learning_count":    learningCount,
		"baseline_count":    baselineCount,
		"anomalous_count":   anomalousCount,
		"learning_mode":     e.config.LearningMode,
		"threshold":         e.config.SuspicionThreshold,
	}
}
