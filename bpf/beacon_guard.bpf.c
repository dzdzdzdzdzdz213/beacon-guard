// SPDX-License-Identifier: GPL-2.0
// BeaconGuard — All eBPF programs in a single file to avoid extern map issues
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

// ─── Maps ─────────────────────────────────────────────────────────────────

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __type(key, u32);
  __type(value, u32);
} suspicion_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, u32);
  __type(value, u32);
} blocklist SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __type(key, u32);
  __type(value, u64);
} process_profiles SEC(".maps");

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

const char sensitive_paths[][32] = {
  "/etc/passwd", "/etc/shadow", "/etc/sudoers",
  "/etc/ssh/sshd_config", "/etc/cron", "/etc/systemd",
  "/boot", "/etc/ld.so.preload", "/proc/sys",
};

// ─── EXECVE MONITOR ────────────────────────────────────────────────────────

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
  u64 *profile = bpf_map_lookup_elem(&process_profiles, &pid);
  if (profile && (*profile & (1ULL << 0))) {
    u32 zero = 0;
    bpf_map_update_elem(&suspicion_map, &pid, &zero, BPF_ANY);
  }
  return 0;
}

// ─── OPEN/FILE MONITOR ────────────────────────────────────────────────────

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint_openat(struct trace_event_raw_sys_enter *ctx) {
  struct event_t *evt;
  evt = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
  if (!evt) return 0;

  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u32 *blocked = bpf_map_lookup_elem(&blocklist, &pid);
  if (blocked) {
    bpf_ringbuf_discard(evt, 0);
    return 1;
  }

  evt->pid = pid;
  evt->type = EVENT_OPEN;
  bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
  const char *filename = (const char *)BPF_CORE_READ(ctx, args[1]);
  bpf_core_read_user_str(evt->file.filename, sizeof(evt->file.filename), filename);
  evt->file.flags = (int)BPF_CORE_READ(ctx, args[2]);

  if (evt->file.flags & MAY_WRITE) {
    u32 *score = bpf_map_lookup_elem(&suspicion_map, &pid);
    if (!score) { u32 init = 10; bpf_map_update_elem(&suspicion_map, &pid, &init, BPF_ANY); }
    else { *score += 10; }
  }

  bpf_ringbuf_submit(evt, 0);
  return 0;
}

SEC("kprobe/security_file_permission")
int kprobe_file_write(struct pt_regs *ctx) {
  struct file *file = (struct file *)PT_REGS_PARM1(ctx);
  int mask = (int)PT_REGS_PARM2(ctx);
  if (!(mask & MAY_WRITE)) return 0;

  struct event_t *evt;
  evt = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
  if (!evt) return 0;

  u32 pid = bpf_get_current_pid_tgid() >> 32;
  evt->pid = pid;
  evt->type = EVENT_WRITE;
  bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

  struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
  struct qstr dname = BPF_CORE_READ(dentry, d_name);
  bpf_core_read_str(evt->file.filename, sizeof(evt->file.filename), dname.name);

  for (int i = 0; i < sizeof(sensitive_paths) / sizeof(sensitive_paths[0]); i++) {
    char c; int match = 1;
    for (int j = 0; j < 32; j++) {
      bpf_core_read(&c, 1, &sensitive_paths[i][j]);
      if (c == '\0') break;
      if (evt->file.filename[j] != c) { match = 0; break; }
    }
    if (match) {
      u32 *score = bpf_map_lookup_elem(&suspicion_map, &pid);
      if (!score) { u32 init = 80; bpf_map_update_elem(&suspicion_map, &pid, &init, BPF_ANY); }
      else { *score += 80; }
      evt->ret = -1;
      break;
    }
  }

  bpf_ringbuf_submit(evt, 0);
  return 0;
}

SEC("kprobe/security_inode_unlink")
int kprobe_file_delete(struct pt_regs *ctx) {
  struct dentry *dentry = (struct dentry *)PT_REGS_PARM2(ctx);
  struct qstr dname;
  bpf_core_read(&dname, sizeof(dname), &dentry->d_name);

  struct event_t *evt;
  evt = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
  if (!evt) return 0;

  u32 pid = bpf_get_current_pid_tgid() >> 32;
  evt->pid = pid;
  evt->type = EVENT_WRITE;
  evt->ret = -2;
  bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
  bpf_core_read_str(evt->file.filename, sizeof(evt->file.filename), dname.name);

  bpf_ringbuf_submit(evt, 0);
  return 0;
}

// ─── NETWORK CONNECT MONITOR ──────────────────────────────────────────────

static __always_inline int is_internal_ip(u32 ip) {
  u8 b1 = ip & 0xFF; u8 b2 = (ip >> 8) & 0xFF;
  if (b1 == 10) return 1;
  if (b1 == 172 && b2 >= 16 && b2 <= 31) return 1;
  if (b1 == 192 && b2 == 168) return 1;
  if (b1 == 127) return 1;
  if (b1 == 169 && b2 == 254) return 1;
  return 0;
}

static __always_inline int is_known_bad_port(u16 port) {
  switch (port) {
    case 4444: case 5555: case 6666: case 6667:
    case 6668: case 6669: case 7777: case 8443:
    case 10000: case 31337: case 4443: return 1;
    default: return 0;
  }
}

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

  struct sock_common *skc = &sk->__sk_common;
  u16 dport = BPF_CORE_READ(skc, skc_dport);
  evt->net.port = bpf_ntohs(dport);
  __be32 daddr = BPF_CORE_READ(skc, skc_daddr);
  bpf_core_read(&evt->net.ip, 4, &daddr);

  u32 ip = *(u32 *)&evt->net.ip;
  int internal = is_internal_ip(ip);
  int bad_port = is_known_bad_port(evt->net.port);

  if (!internal && bad_port) {
    u32 *score = bpf_map_lookup_elem(&suspicion_map, &pid);
    if (!score) { u32 init = 60; bpf_map_update_elem(&suspicion_map, &pid, &init, BPF_ANY); }
    else { *score += 60; }
    evt->ret = 1;
  }

  bpf_ringbuf_submit(evt, 0);
  return 0;
}

SEC("kprobe/udp_sendmsg")
int kprobe_udp_send(struct pt_regs *ctx) {
  struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
  struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);

  struct sock_common *skc = &sk->__sk_common;
  u16 dport = BPF_CORE_READ(skc, skc_dport);
  dport = bpf_ntohs(dport);
  if (dport != 53) return 0;

  struct event_t *evt;
  evt = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
  if (!evt) return 0;

  u32 pid = bpf_get_current_pid_tgid() >> 32;
  evt->pid = pid;
  evt->type = EVENT_CONNECT;
  evt->net.port = 53;
  evt->net.domain = AF_INET;
  bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
  __be32 daddr = BPF_CORE_READ(skc, skc_daddr);
  bpf_core_read(&evt->net.ip, 4, &daddr);

  size_t msg_len = BPF_CORE_READ(msg, msg_iter.count);
  if (msg_len > 512) {
    evt->ret = 1;
    u32 *score = bpf_map_lookup_elem(&suspicion_map, &pid);
    if (!score) { u32 init = 30; bpf_map_update_elem(&suspicion_map, &pid, &init, BPF_ANY); }
    else { *score += 30; }
  }

  bpf_ringbuf_submit(evt, 0);
  return 0;
}

// ─── PROCESS TRACKER ──────────────────────────────────────────────────────

SEC("tracepoint/syscalls/sys_enter_clone")
int tracepoint_clone(struct trace_event_raw_sys_enter *ctx) {
  struct proc_key key = {};
  struct proc_info info = {};
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u32 tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
  key.pid = pid; key.tgid = tgid;
  info.ppid = tgid;
  info.start_time = bpf_ktime_get_ns();
  bpf_get_current_comm(info.comm, sizeof(info.comm));
  bpf_map_update_elem(&proc_table, &key, &info, BPF_ANY);

  struct event_t *evt;
  evt = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
  if (evt) {
    evt->pid = pid; evt->type = EVENT_FORK; evt->ppid = tgid;
    bpf_get_current_comm(evt->comm, sizeof(evt->comm));
    bpf_ringbuf_submit(evt, 0);
  }
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_exit_group")
int tracepoint_exit(struct trace_event_raw_sys_exit *ctx) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u32 tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
  struct proc_key key = { .pid = pid, .tgid = tgid };
  bpf_map_delete_elem(&proc_table, &key);
  return 0;
}

// ─── MMAP EXEC MONITOR ────────────────────────────────────────────────────

SEC("kprobe/vm_mmap_pgoff")
int kprobe_mmap_exec(struct pt_regs *ctx) {
  unsigned long prot = (unsigned long)PT_REGS_PARM3(ctx);
  if (!(prot & PROT_EXEC)) return 0;

  struct event_t *evt;
  evt = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
  if (!evt) return 0;

  u32 pid = bpf_get_current_pid_tgid() >> 32;
  evt->pid = pid;
  evt->type = EVENT_MMAP_EXEC;
  bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

  u32 *score = bpf_map_lookup_elem(&suspicion_map, &pid);
  if (!score) { u32 init = 20; bpf_map_update_elem(&suspicion_map, &pid, &init, BPF_ANY); }
  else { *score += 20; }

  bpf_ringbuf_submit(evt, 0);
  return 0;
}

// ─── PTRACE MONITOR ───────────────────────────────────────────────────────

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

  if (target_pid != evt->ppid) {
    u32 *score = bpf_map_lookup_elem(&suspicion_map, &pid);
    if (!score) { u32 init = 50; bpf_map_update_elem(&suspicion_map, &pid, &init, BPF_ANY); }
    else { *score += 50; }
    evt->ret = target_pid;
  }

  bpf_ringbuf_submit(evt, 0);
  return 0;
}
