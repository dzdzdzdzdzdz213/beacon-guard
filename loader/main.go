package main

import (
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

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	spec, err := ebpf.LoadCollectionSpec("../bpf/syscall_monitor.bpf.o")
	if err != nil {
		log.Fatalf("Failed to load BPF spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create BPF collection: %v", err)
	}
	defer coll.Close()

	eventsMap, ok := coll.Maps["events"]
	if !ok {
		log.Fatalf("events map not found in BPF object")
	}

	processor := NewEventProcessor(config)
	engine = NewEngine(config)
	processor.Start(eventsMap, engine)

	apiServer := NewAPIServer(engine, config)
	go apiServer.startAlertConsumer()
	go apiServer.Start(config.APIPort)

	log.Printf("BeaconGuard v%s loaded and monitoring", version)
	log.Printf("Suspicion threshold: %d", config.SuspicionThreshold)
	log.Printf("Learning mode: %v", config.LearningMode)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Shutting down...")
}
