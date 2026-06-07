// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

// Ring buffer to send events to userspace
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

// Map of suspicious process chains (pid -> parent suspicion score)
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __type(key, u32);
  __type(value, u32);
} suspicion_map SEC(".maps");

// Blocklist for immediate denial
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, u32);
  __type(value, u32);
} blocklist SEC(".maps");

// Per-process baseline profiles (pid -> behavior bitmap)
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __type(key, u32);
  __type(value, u64);
} process_profiles SEC(".maps");

// ---------- EXECVE MONITOR ----------
SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint_execve(struct trace_event_raw_sys_enter *ctx) {
  struct event_t *evt;
  evt = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
  if (!evt) return 0;

  u32 pid = bpf_get_current_pid_tgid() >> 32;
  evt->pid = pid;
  evt->ppid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
  evt->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
  evt->type = EVENT_EXECVE;

  bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

  const char *filename = (const char *)BPF_CORE_READ(ctx, args[0]);
  bpf_core_read_user_str(evt->exec.filename, sizeof(evt->exec.filename), filename);

  const char *argv = (const char *)BPF_CORE_READ(ctx, args[1]);
  bpf_core_read_user_str(evt->exec.argv, sizeof(evt->exec.argv), argv);

  bpf_ringbuf_submit(evt, 0);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint_execve_exit(struct trace_event_raw_sys_exit *ctx) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u32 *score = bpf_map_lookup_elem(&suspicion_map, &pid);
  if (!score) return 0;

  // Reset suspicion on successful exec of trusted binary
  u64 *profile = bpf_map_lookup_elem(&process_profiles, &pid);
  if (profile && (*profile & (1ULL << 0))) {
    u32 zero = 0;
    bpf_map_update_elem(&suspicion_map, &pid, &zero, BPF_ANY);
  }
  return 0;
}

// ---------- OPEN MONITOR ----------
SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint_openat(struct trace_event_raw_sys_enter *ctx) {
  struct event_t *evt;
  evt = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
  if (!evt) return 0;

  u32 pid = bpf_get_current_pid_tgid() >> 32;

  // Check blocklist
  u32 *blocked = bpf_map_lookup_elem(&blocklist, &pid);
  if (blocked) {
    bpf_ringbuf_discard(evt, 0);
    return 1; // Block the syscall
  }

  evt->pid = pid;
  evt->type = EVENT_OPEN;
  bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

  const char *filename = (const char *)BPF_CORE_READ(ctx, args[1]);
  bpf_core_read_user_str(evt->file.filename, sizeof(evt->file.filename), filename);
  evt->file.flags = (int)BPF_CORE_READ(ctx, args[2]);

  // Flag writes to sensitive paths
  if (evt->file.flags & 0x2) {
    u32 *score = bpf_map_lookup_elem(&suspicion_map, &pid);
    if (!score) {
      u32 init = 10;
      bpf_map_update_elem(&suspicion_map, &pid, &init, BPF_ANY);
    } else {
      *score += 10;
    }
  }

  bpf_ringbuf_submit(evt, 0);
  return 0;
}

// ---------- CONNECT MONITOR ----------
SEC("kprobe/tcp_v4_connect")
int kprobe_tcp_connect(struct pt_regs *ctx) {
  struct event_t *evt;
  evt = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
  if (!evt) return 0;

  u32 pid = bpf_get_current_pid_tgid() >> 32;
  struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

  evt->pid = pid;
  evt->type = EVENT_CONNECT;
  bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

  evt->net.domain = AF_INET;
  evt->net.sock_fd = (int)PT_REGS_PARM2(ctx);

  // Read destination address
  struct sock_common *skc = &sk->__sk_common;
  u16 dport = BPF_CORE_READ(skc, skc_dport);
  evt->net.port = bpf_ntohs(dport);

  struct in6_addr *addr = &skc->skc_daddr;
  bpf_core_read(&evt->net.ip, 4, &addr->in6_u.u6_addr32);

  // Known malicious IPs (C2, mining pools, etc.)
  u32 ip = *(u32 *)&evt->net.ip;
  u32 known_bad[] = { 0x0100007F, 0 }; // 127.0.0.1 for testing
  for (int i = 0; known_bad[i] != 0; i++) {
    if (ip == known_bad[i]) {
      evt->ret = -1;
      bpf_ringbuf_submit(evt, 0);
      return -1; // Block connection
    }
  }

  bpf_ringbuf_submit(evt, 0);
  return 0;
}

// ---------- MMAP EXEC MONITOR ----------
SEC("kprobe/vm_mmap_pgoff")
int kprobe_mmap_exec(struct pt_regs *ctx) {
  unsigned long prot = (unsigned long)PT_REGS_PARM3(ctx);
  if (!(prot & 0x4)) return 0; // Not executable

  struct event_t *evt;
  evt = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
  if (!evt) return 0;

  u32 pid = bpf_get_current_pid_tgid() >> 32;
  evt->pid = pid;
  evt->type = EVENT_MMAP_EXEC;
  bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

  // Raise suspicion
  u32 *score = bpf_map_lookup_elem(&suspicion_map, &pid);
  if (!score) {
    u32 init = 20;
    bpf_map_update_elem(&suspicion_map, &pid, &init, BPF_ANY);
  } else {
    *score += 20;
  }

  bpf_ringbuf_submit(evt, 0);
  return 0;
}

// ---------- PTRACE MONITOR ----------
SEC("kprobe/security_ptrace_access_check")
int kprobe_ptrace(struct pt_regs *ctx) {
  struct task_struct *child = (struct task_struct *)PT_REGS_PARM1(ctx);

  struct event_t *evt;
  evt = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
  if (!evt) return 0;

  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u32 target_pid = BPF_CORE_READ(child, pid);

  evt->pid = pid;
  evt->type = EVENT_PTRACE;
  bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

  // ptrace to non-child is suspicious
  if (target_pid != evt->ppid) {
    u32 *score = bpf_map_lookup_elem(&suspicion_map, &pid);
    if (!score) {
      u32 init = 50;
      bpf_map_update_elem(&suspicion_map, &pid, &init, BPF_ANY);
    } else {
      *score += 50;
    }
    evt->ret = target_pid;
  }

  bpf_ringbuf_submit(evt, 0);
  return 0;
}
