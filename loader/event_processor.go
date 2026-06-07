package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

type EventProcessor struct {
	config *Config
	stats  *Stats
}

type Stats struct {
	EventsProcessed   int64
	AnomaliesDetected int64
	ProcessesKilled   int64
	StartTime         time.Time
}

func NewEventProcessor(config *Config) *EventProcessor {
	return &EventProcessor{
		config: config,
		stats: &Stats{
			StartTime: time.Now(),
		},
	}
}

func (ep *EventProcessor) Start(eventsMap *ebpf.Map, engine *Engine) {
	reader, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		log.Fatalf("Failed to create ringbuf reader: %v", err)
	}
	defer reader.Close()

	log.Println("Event processor started")

	for {
		record, err := reader.Read()
		if err != nil {
			log.Printf("Error reading from ringbuf: %v", err)
			continue
		}

		ep.stats.EventsProcessed++

		if len(record.RawSample) == 0 {
			continue
		}

		event := parseEvent(record.RawSample)
		if event == nil {
			continue
		}

		anomaly := engine.Analyze(event)
		if anomaly != nil {
			ep.stats.AnomaliesDetected++
			ep.handleAnomaly(anomaly)
		}
	}
}

type Event struct {
	Pid  int                    `json:"pid"`
	Ppid int                    `json:"ppid"`
	Uid  int                    `json:"uid"`
	Gid  int                    `json:"gid"`
	Ret  int                    `json:"ret"`
	Type int                    `json:"type"`
	Comm string                 `json:"comm"`
	Data map[string]interface{} `json:"data"`
}

func parseEvent(raw []byte) *Event {
	if len(raw) < 32 {
		return nil
	}

	evt := &Event{
		Pid:  int(binary.LittleEndian.Uint32(raw[0:4])),
		Ppid: int(binary.LittleEndian.Uint32(raw[4:8])),
		Uid:  int(binary.LittleEndian.Uint32(raw[8:12])),
		Gid:  int(binary.LittleEndian.Uint32(raw[12:16])),
		Ret:  int(binary.LittleEndian.Uint32(raw[16:20])),
		Type: int(binary.LittleEndian.Uint32(raw[20:24])),
		Comm: cStrToString(raw[24:40]),
		Data: make(map[string]interface{}),
	}

	switch evt.Type {
	case 1: // EXECVE
		evt.Data["filename"] = cStrToString(raw[40:296])
		evt.Data["argv"] = cStrToString(raw[296:360])
	case 2: // OPEN
		evt.Data["filename"] = cStrToString(raw[40:296])
		evt.Data["flags"] = int(binary.LittleEndian.Uint32(raw[296:300]))
	case 3: // CONNECT
		evt.Data["sock_fd"] = int(binary.LittleEndian.Uint32(raw[40:44]))
		evt.Data["port"] = int(binary.LittleEndian.Uint16(raw[44:46]))
		evt.Data["ip"] = fmt.Sprintf("%d.%d.%d.%d",
			raw[46], raw[47], raw[48], raw[49])
		evt.Data["domain"] = int(binary.LittleEndian.Uint32(raw[50:54]))
	case 5: // MMAP_EXEC
	case 8: // PTRACE
		evt.Data["target_pid"] = evt.Ret
	}

	return evt
}

func (ep *EventProcessor) handleAnomaly(anomaly *Anomaly) {
	alert := map[string]interface{}{
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
		"severity":    anomaly.Severity,
		"rule":        anomaly.Rule,
		"description": anomaly.Description,
		"pid":         anomaly.Pid,
		"comm":        anomaly.Comm,
		"score":       anomaly.Score,
		"action":      anomaly.Action,
		"details":     anomaly.Details,
	}

	alertJSON, _ := json.Marshal(alert)
	log.Printf("ANOMALY: %s", string(alertJSON))

	sendToAPI(alert)

	if ep.config.AutoKill && anomaly.Action == "kill" {
		log.Printf("KILLING process %d (%s)", anomaly.Pid, anomaly.Comm)
		ep.stats.ProcessesKilled++
		killProcess(anomaly.Pid)
	}
}

func cStrToString(data []byte) string {
	for i, b := range data {
		if b == 0 {
			return string(data[:i])
		}
	}
	return string(data)
}

func sendToAPI(alert map[string]interface{}) {
	select {
	case alertChan <- alert:
	default:
	}
	// Also forward to Python API
	go func() {
		data, _ := json.Marshal(alert)
		http.Post("http://localhost:9091/api/v1/alerts", "application/json", bytes.NewReader(data))
	}()
}

func killProcess(pid int) {
	proc, err := os.FindProcess(pid)
	if err == nil {
		proc.Signal(syscall.SIGKILL)
	}
}

var alertChan = make(chan map[string]interface{}, 1000)
