<div align="center">

# BeaconGuard

**Real-time process anomaly detection powered by eBPF**

[![License: GPL-2.0](https://img.shields.io/badge/License-GPL_2.0-blue.svg)](https://opensource.org/licenses/GPL-2.0)
[![Language: C/Go](https://img.shields.io/badge/Language-C%20%7C%20Go-00ADD8.svg)]()
[![Stars](https://img.shields.io/github/stars/dzdzdzdzdzdz213/beacon-guard?style=social)]()
[![Status: Active](https://img.shields.io/badge/Status-Active-brightgreen.svg)]()

</div>

---

## Overview

BeaconGuard is a lightweight kernel-level security monitor that leverages eBPF to observe and enforce behavioral baselines for running processes. It hooks into nine critical kernel subsystems to detect anomalous activity in real time and can automatically terminate compromised processes before damage spreads. Designed for production Linux environments, it streams structured telemetry via Server-Sent Events for seamless integration with existing observability stacks.

## Features

- **9 eBPF Kernel Hooks** -- Monitors `execve`, `connect`, `open`, `write`, `mmap`, `clone`, `ptrace`, `mount`, and `kill` syscalls
- **Behavioral Baselines** -- Learns per-process behavior profiles during a calibration window, then flags deviations automatically
- **Auto-Kill Engine** -- Terminates processes that exceed configurable anomaly thresholds within configurable response windows
- **SSE Telemetry Streaming** -- Pushes structured alert payloads to any HTTP consumer in real time
- **Low Overhead** -- Sub-2% CPU impact under sustained workload due to efficient eBPF map utilization
- **Kernel-Version Agnostic** -- Supports kernels 5.4+ with automatic feature detection and graceful degradation

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    User Space                            │
│                                                         │
│  ┌──────────────┐   ┌──────────────┐   ┌────────────┐  │
│  │  Go Control  │   │  SSE Server  │   │  Config &  │  │
│  │    Plane     │──▶│   (port 8080)│   │  Rules YAML│  │
│  └──────┬───────┘   └──────▲───────┘   └─────┬──────┘  │
│         │                  │                 │          │
│─────────┼──────────────────┼─────────────────┼──────────│
│         │      Kernel Space (eBPF)           │          │
│  ┌──────┴──────────────────┴─────────────────┴──────┐   │
│  │              eBPF Program Array                  │   │
│  │  execve │ connect │ open │ write │ mmap │ clone  │   │
│  │  ptrace │ mount   │ kill                          │   │
│  └──────────────────────┬───────────────────────────┘   │
│                         │                               │
│                    ┌────┴────┐                           │
│                    │  eBPF   │                           │
│                    │  Maps   │                           │
│                    └─────────┘                           │
└─────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Clone the repository
git clone https://github.com/dzdzdzdzdzdz213/beacon-guard.git
cd beacon-guard

# Build the eBPF programs and Go control plane
make build

# Run with default configuration
sudo ./beacon-guard --config config.yaml --rules rules.yaml

# Attach SSE listener
curl -N http://localhost:8080/events
```

## Tech Stack

| Component        | Technology       | Purpose                          |
|------------------|------------------|----------------------------------|
| Kernel Hooks     | C / libbpf       | eBPF program compilation         |
| Control Plane    | Go               | Lifecycle management, alerting   |
| Data Transport   | Server-Sent Events | Real-time telemetry streaming  |
| Configuration    | YAML             | Rule definitions and thresholds  |
| Containerization | Docker           | Reproducible deployment          |
| Target Platform  | Linux 5.4+       | Kernel compatibility             |

## License

[![License: GPL-2.0](https://img.shields.io/badge/License-GPL_2.0-blue.svg)](https://opensource.org/licenses/GPL-2.0)

This project is licensed under the GNU General Public License v2.0.
