// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

extern struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events;

// Track parent-child relationships
struct proc_key {
  u32 pid;
  u32 tgid;
};

struct proc_info {
  u32 ppid;
  u64 start_time;
  char comm[MAX_COMM];
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __type(key, struct proc_key);
  __type(value, struct proc_info);
} proc_table SEC(".maps");

// Fork tracker
SEC("tracepoint/syscalls/sys_enter_clone")
int tracepoint_clone(struct trace_event_raw_sys_enter *ctx) {
  struct proc_key key = {};
  struct proc_info info = {};

  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u32 tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

  key.pid = pid;
  key.tgid = tgid;
  info.ppid = tgid;
  info.start_time = bpf_ktime_get_ns();
  bpf_get_current_comm(info.comm, sizeof(info.comm));

  bpf_map_update_elem(&proc_table, &key, &info, BPF_ANY);

  // Emit fork event
  struct event_t *evt;
  evt = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
  if (evt) {
    evt->pid = pid;
    evt->type = EVENT_FORK;
    evt->ppid = tgid;
    bpf_get_current_comm(evt->comm, sizeof(evt->comm));
    bpf_ringbuf_submit(evt, 0);
  }

  return 0;
}

// Process exit — clean up + emit anomaly if short-lived and suspicious
SEC("tracepoint/syscalls/sys_exit_exit_group")
int tracepoint_exit(struct trace_event_raw_sys_exit *ctx) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u32 tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

  struct proc_key key = { .pid = pid, .tgid = tgid };
  bpf_map_delete_elem(&proc_table, &key);

  return 0;
}
