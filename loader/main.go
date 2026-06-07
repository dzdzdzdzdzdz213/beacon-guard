package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

var version = "0.1.0"

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "config.json", "Path to configuration file")
	var showVersion bool
	flag.BoolVar(&showVersion, "version", false, "Show version")
	flag.Parse()

	if showVersion {
		fmt.Printf("BeaconGuard loader v%s\n", version)
		os.Exit(0)
	}

	config, err := loadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Allow the current process to lock memory for eBPF maps
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	// Load the compiled BPF object
	spec, err := ebpf.LoadCollectionSpec("beacon_guard.bpf.o")
	if err != nil {
		log.Fatalf("Failed to load BPF spec: %v", err)
	}

	var objs bpfObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("Failed to load BPF objects: %v", err)
	}
	defer objs.Close()

	// Create ring buffer reader
	reader, err := ebpf.NewReader(objs.Events, 8192)
	if err != nil {
		log.Fatalf("Failed to create ringbuf reader: %v", err)
	}
	defer reader.Close()

	// Initialize processing pipeline
	processor := NewEventProcessor(config)
	engine = NewEngine(config)

	// Start API server
	apiServer := NewAPIServer(engine, config)
	apiServer.startAlertConsumer()
	go apiServer.Start(config.APIPort)

	go processor.Start(reader, engine)

	log.Printf("BeaconGuard v%s loaded and monitoring", version)
	log.Printf("Suspicion threshold: %d", config.SuspicionThreshold)
	log.Printf("Learning mode: %v", config.LearningMode)

	if config.LearningMode {
		log.Println("BEACONGUARD IS IN LEARNING MODE — establishing baseline profiles")
	} else {
		log.Println("BEACONGUARD IS IN ENFORCEMENT MODE — anomalies will be blocked")
	}

	// Wait for shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Shutting down...")
}
