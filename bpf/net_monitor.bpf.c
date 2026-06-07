// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
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

static __always_inline int is_internal_ip(u32 ip) {
  u8 b1 = ip & 0xFF;
  u8 b2 = (ip >> 8) & 0xFF;

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
    case 10000: case 31337: case 4443:
      return 1;
    default:
      return 0;
  }
}

// UDP — DNS tunneling detection
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
    if (!score) {
      u32 init = 30;
      bpf_map_update_elem(&suspicion_map, &pid, &init, BPF_ANY);
    } else {
      *score += 30;
    }
  }

  bpf_ringbuf_submit(evt, 0);
  return 0;
}

// TCP connect with enhanced checks
SEC("kprobe/tcp_v4_connect")
int kprobe_tcp_connect_enhanced(struct pt_regs *ctx) {
  struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

  struct event_t *evt;
  evt = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
  if (!evt) return 0;

  u32 pid = bpf_get_current_pid_tgid() >> 32;
  evt->pid = pid;
  evt->type = EVENT_CONNECT;
  bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

  struct sock_common *skc = &sk->__sk_common;
  u16 dport = BPF_CORE_READ(skc, skc_dport);
  evt->net.port = bpf_ntohs(dport);
  evt->net.domain = AF_INET;

  __be32 daddr = BPF_CORE_READ(skc, skc_daddr);
  bpf_core_read(&evt->net.ip, 4, &daddr);

  u32 ip4 = *(u32 *)&evt->net.ip;
  int internal = is_internal_ip(ip4);
  int bad_port = is_known_bad_port(evt->net.port);

  if (!internal && bad_port) {
    u32 *score = bpf_map_lookup_elem(&suspicion_map, &pid);
    if (!score) {
      u32 init = 60;
      bpf_map_update_elem(&suspicion_map, &pid, &init, BPF_ANY);
    } else {
      *score += 60;
    }
    evt->ret = 1;
  }

  bpf_ringbuf_submit(evt, 0);
  return 0;
}
