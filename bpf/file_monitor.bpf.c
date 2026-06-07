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

extern struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __type(key, u32);
  __type(value, u32);
} suspicion_map;

// Sensitive paths that should rarely be written to
const char sensitive_paths[][32] = {
  "/etc/passwd",
  "/etc/shadow",
  "/etc/sudoers",
  "/etc/ssh/sshd_config",
  "/etc/cron",
  "/etc/systemd",
  "/boot",
  "/etc/ld.so.preload",
  "/proc/sys",
};

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

  // Read dentry path
  struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
  struct qstr dname = BPF_CORE_READ(dentry, d_name);
  bpf_core_read_str(evt->file.filename, sizeof(evt->file.filename), dname.name);

  // Check against sensitive paths
  for (int i = 0; i < sizeof(sensitive_paths) / sizeof(sensitive_paths[0]); i++) {
    char c;
    int match = 1;
    for (int j = 0; j < 32; j++) {
      bpf_core_read(&c, 1, &sensitive_paths[i][j]);
      if (c == '\0') break;
      if (evt->file.filename[j] != c) { match = 0; break; }
    }
    if (match) {
      u32 *score = bpf_map_lookup_elem(&suspicion_map, &pid);
      if (!score) {
        u32 init = 80;
        bpf_map_update_elem(&suspicion_map, &pid, &init, BPF_ANY);
      } else {
        *score += 80;
      }
      evt->ret = -1;
      break;
    }
  }

  bpf_ringbuf_submit(evt, 0);
  return 0;
}

// Track file deletions
SEC("kprobe/security_inode_unlink")
int kprobe_file_delete(struct pt_regs *ctx) {
  struct dentry *dentry = (struct dentry *)PT_REGS_PARM2(ctx);

  struct qstr dname;
  bpf_core_read(&dname, sizeof(dname), &dentry->d_name);

  char filename[MAX_FILE_PATH] = {};
  bpf_core_read_str(filename, sizeof(filename), dname.name);

  // Ransomware detection: rapid file deletions
  struct event_t *evt;
  evt = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
  if (!evt) return 0;

  u32 pid = bpf_get_current_pid_tgid() >> 32;
  evt->pid = pid;
  evt->type = EVENT_WRITE;
  evt->ret = -2; // -2 = delete
  bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
  __builtin_memcpy(evt->file.filename, filename, sizeof(filename));

  bpf_ringbuf_submit(evt, 0);
  return 0;
}
