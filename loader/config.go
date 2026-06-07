package main

import (
	"encoding/json"
	"os"
)

type Config struct {
	// Alerting
	WebhookURL string `json:"webhook_url"`
	SyslogEndpoint string `json:"syslog_endpoint"`

	// Engine
	SuspicionThreshold int `json:"suspicion_threshold"`
	LearningMode       bool `json:"learning_mode"`
	AutoKill           bool `json:"auto_kill"`

	// API
	APIPort int `json:"api_port"`

	// Monitoring scope
	MonitorPIDs  []int    `json:"monitor_pids"`
	MonitorUsers []string `json:"monitor_users"`
	ExcludePIDs  []int    `json:"exclude_pids"`

	// Known bad
	KnownBadIPs   []string `json:"known_bad_ips"`
	KnownBadHashes []string `json:"known_bad_hashes"`

	// Behavioral
	BaselineWindowSec int `json:"baseline_window_sec"`
	MaxConnectionsPerMin int `json:"max_connections_per_min"`
	MaxFileWritesPerMin int `json:"max_file_writes_per_min"`
	AllowedExecutables []string `json:"allowed_executables"`

	// Response
	ResponseAction string `json:"response_action"` // "alert", "block", "kill"
}

func DefaultConfig() *Config {
	return &Config{
		SuspicionThreshold:   100,
		LearningMode:         true,
		AutoKill:             false,
		APIPort:              9090,
		BaselineWindowSec:    3600,
		MaxConnectionsPerMin: 50,
		MaxFileWritesPerMin:  100,
		ResponseAction:       "alert",
	}
}

func loadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}
