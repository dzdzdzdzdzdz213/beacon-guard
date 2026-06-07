# BeaconGuard — Behavioral Kernel Guard

An eBPF-based runtime security monitor that hooks kernel syscalls, builds per-process behavioral baselines, and kills anomalous processes in real time. No signatures. No static rules. Pure behavior.

## How It Works

```
Process behavior  →  eBPF kernel hooks (execve, open, connect, mmap, ptrace)
                  →  Ring buffer →  Go userspace loader
                  →  Behavioral engine (profile + baseline + anomaly)
                  →  Kill / Block / Alert
                  →  FastAPI  →  React dashboard (SSE)
```

## eBPF Hooks

| Hook | Tracks | Threat Detection |
|------|--------|-----------------|
| `tracepoint_execve` | Binary execution | Unexpected binaries, shell spawning |
| `tracepoint_openat` | File operations | Sensitive file writes, mass deletion |
| `kprobe_tcp_connect` | Outbound connections | Beaconing, C2, reverse shells |
| `kprobe_udp_sendmsg` | DNS queries | DNS tunneling (>512 bytes) |
| `kprobe_mmap_exec` | Executable memory | Code injection, shellcode |
| `kprobe_ptrace` | Process debugging | Injection attempts |

## Detection Rules

| Rule | Severity | Action | Description |
|------|----------|--------|-------------|
| `beaconing_detected` | Critical | Kill | Periodic external connections (low variance timing) |
| `reverse_shell_port` | Critical | Kill | Connection to known C2 ports (4444, 31337, etc.) |
| `mass_file_deletion` | Critical | Kill | Ransomware-style rapid deletions |
| `sensitive_file_write` | Critical | Block | Write to /etc/passwd, /etc/shadow, etc. |
| `dns_tunneling` | High | Alert | Oversized DNS queries (>512 bytes) |
| `unexpected_binary` | High | Alert | Binary not seen in baseline period |
| `rapid_succession_connections` | High | Alert | Many external IPs in short window |
| `ptrace_attachment` | High | Alert | Debug attach to non-child process |
| `process_running_as_root` | Medium | Alert | Root execution without baseline |
| `executable_mmap` | Medium | Alert | W+X memory mapping |

## Architecture

```
┌─────────────────────────────────────────────────┐
│  Kernel (eBPF)                                   │
│  ┌───────────┐ ┌──────────┐ ┌─────────────────┐  │
│  │ Syscall   │ │ Ring     │ │ Suspicion Map   │  │
│  │ Hooks (C) │ │ Buffer   │ │ (per-process)   │  │
│  └───────────┘ └────┬─────┘ └────────┬────────┘  │
├──────────────────────┼────────────────┼───────────┤
│  Userspace (Go)      │                │           │
│  ┌───────────────────▼────┐  ┌────────▼────────┐  │
│  │ Event Processor       │  │ API Server      │  │
│  │ Parse events          │  │ REST + SSE      │  │
│  └───────────────────┬────┘  └────────┬────────┘  │
│  ┌───────────────────▼────┐           │           │
│  │ Behavioral Engine      │           │           │
│  │ Profile → Baseline     │           │           │
│  │ → Anomaly Detection    │           │           │
│  └───────────────────┬────┘           │           │
│                      │                │           │
├──────────────────────┼────────────────┼───────────┤
│  Python              │                │           │
│  ┌───────────────────▼────────────────▼────────┐  │
│  │ FastAPI Backend (alert storage, config)      │  │
│  └──────────────────────────────────────────────┘  │
│                                                    │
│  ┌──────────────────────────────────────────────┐  │
│  │ React Dashboard (timeline, process table,    │  │
│  │ alert feed, stats)                           │  │
│  └──────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites
- Linux kernel 5.4+ with BPF support
- `clang`, `llvm-strip`, `bpftool`, `libbpf-dev`
- Go 1.22+, Python 3.11+, Node 18+

### Build and Run

```bash
# 1. Build eBPF objects
cd bpf
make
cd ..

# 2. Build Go loader
cd loader
go build -o beacon-guard .
cd ..

# 3. Start the loader (learning mode)
sudo ./loader/beacon-guard --config config.json

# 4. Start the API server (separate terminal)
cd api
pip install -r requirements.txt
python main.py

# 5. Start the dashboard (separate terminal)
cd frontend
npm install
npm start
```

Or use Docker Compose:

```bash
docker-compose up --build
```

### Configuration

Edit `config.json`:

```json
{
  "learning_mode": true,
  "suspicion_threshold": 100,
  "auto_kill": false,
  "api_port": 9090,
  "baseline_window_sec": 3600,
  "max_connections_per_min": 50,
  "max_file_writes_per_min": 100,
  "allowed_executables": ["/usr/bin/ssh", "/usr/bin/curl", "/usr/bin/wget"],
  "known_bad_ips": ["1.2.3.4"],
  "response_action": "alert"
}
```

### Learning Mode

Start in learning mode to establish baselines:
- Records normal process behavior for 1 hour
- No alerts or blocks during this period
- After baseline, switches to enforcement automatically

### Enforcement Mode

When enforcement is active:
- Processes exceeding suspicion threshold are killed
- Suspicious events generate real-time alerts
- Dashboard shows live process states

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/health` | Health check |
| GET | `/api/v1/stats` | Aggregated statistics |
| GET | `/api/v1/alerts` | Alert history |
| POST | `/api/v1/alerts` | Ingest alert from Go loader |
| GET | `/api/v1/alerts/stream` | SSE stream (real-time) |
| GET | `/api/v1/processes` | Tracked processes |
| GET | `/api/v1/config` | Current configuration |
| POST | `/api/v1/config` | Update configuration |

## License

GPL-2.0 (eBPF programs require GPL-compatible license)
