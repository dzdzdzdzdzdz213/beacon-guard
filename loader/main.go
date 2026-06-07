package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

var version = "0.1.0"

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "config.json", "Path to configuration file")
	var bpfDir string
	flag.StringVar(&bpfDir, "bpf-dir", "", "Directory containing .bpf.o files (default: <binary_dir>/../bpf/)")
	var showVersion bool
	flag.BoolVar(&showVersion, "version", false, "Show version")
	flag.Parse()

	if showVersion {
		fmt.Printf("BeaconGuard loader v%s\n", version)
		os.Exit(0)
	}

	if bpfDir == "" {
		exe, err := os.Executable()
		if err == nil {
			bpfDir = filepath.Join(filepath.Dir(exe), "..", "bpf")
		} else {
			bpfDir = "bpf"
		}
	}

	config, err := loadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	spec, err := ebpf.LoadCollectionSpec(filepath.Join(bpfDir, "beacon_guard.bpf.o"))
	if err != nil {
		log.Fatalf("Failed to load BPF spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create BPF collection: %v", err)
	}
	defer coll.Close()

	// Debug: list loaded programs
	log.Printf("Loaded programs:")
	for name := range coll.Programs {
		log.Printf("  - %s", name)
	}

	// ─── Attach programs to kernel hooks ───────────────────────────────
	type attach struct {
		name     string
		typ      string // "tracepoint" or "kprobe"
		category string // tracepoint category or kprobe symbol
		event    string // tracepoint name
	}

	attachments := []attach{
		{"tracepoint_execve", "tracepoint", "syscalls", "sys_enter_execve"},
		{"tracepoint_execve_exit", "tracepoint", "syscalls", "sys_exit_execve"},
		{"tracepoint_openat", "tracepoint", "syscalls", "sys_enter_openat"},
		{"tracepoint_clone", "tracepoint", "syscalls", "sys_enter_clone"},
		{"tracepoint_exit", "tracepoint", "syscalls", "sys_exit_exit_group"},
		{"kprobe_tcp_connect", "kprobe", "", "tcp_v4_connect"},
		{"kprobe_udp_send", "kprobe", "", "udp_sendmsg"},
		{"kprobe_mmap_exec", "kprobe", "", "vm_mmap_pgoff"},
		{"kprobe_ptrace", "kprobe", "", "security_ptrace_access_check"},
		{"kprobe_file_write", "kprobe", "", "security_file_permission"},
		{"kprobe_file_delete", "kprobe", "", "security_inode_unlink"},
	}

	links := []link.Link{}

	for _, a := range attachments {
		prog := coll.Programs[a.name]
		if prog == nil {
			log.Printf("  Program %s NOT FOUND in collection, skipping", a.name)
			continue
		}
		var l link.Link
		var err error
		switch a.typ {
		case "tracepoint":
			l, err = link.Tracepoint(a.category, a.event, prog, nil)
		case "kprobe":
			l, err = link.Kprobe(a.event, prog, nil)
		}
		if err != nil {
			log.Printf("  Failed to attach %s: %v", a.name, err)
			continue
		}
		links = append(links, l)
		log.Printf("  Attached %s (%s)", a.name, a.typ)
	}

	if len(links) == 0 {
		log.Fatal("No programs could be attached")
	}

	eventsMap, ok := coll.Maps["events"]
	if !ok {
		log.Fatal("events map not found in BPF object")
	}

	processor := NewEventProcessor(config)
	engine = NewEngine(config)

	apiServer := NewAPIServer(engine, config)
	go apiServer.startAlertConsumer()
	go apiServer.Start(config.APIPort)
	go processor.Start(eventsMap, engine)

	log.Printf("BeaconGuard v%s loaded and monitoring (%d hooks attached)", version, len(links))

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Shutting down...")
	for _, l := range links {
		l.Close()
	}
}
