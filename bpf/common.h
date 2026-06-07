#ifndef __COMMON_H
#define __COMMON_H

// Kernel constants not exposed in vmlinux.h
#define MAY_WRITE 2
#define AF_INET 2
#define PROT_EXEC 4

#define MAX_PATH 256
#define MAX_COMM 16
#define MAX_ARGS 64
#define MAX_FILE_PATH 256
#define MAX_BUF 4096

struct event_t {
  int pid;
  int ppid;
  int uid;
  int gid;
  int ret;
  int type;
  char comm[MAX_COMM];
  union {
    struct {
      char filename[MAX_PATH];
      char argv[MAX_ARGS];
    } exec;
    struct {
      char filename[MAX_PATH];
      int flags;
    } file;
    struct {
      int sock_fd;
      unsigned long sa;
      unsigned short port;
      char ip[40];
      int domain;
      int type_proto;
    } net;
  };
};

enum event_type {
  EVENT_EXECVE = 1,
  EVENT_OPEN = 2,
  EVENT_CONNECT = 3,
  EVENT_BIND = 4,
  EVENT_MMAP_EXEC = 5,
  EVENT_FORK = 6,
  EVENT_WRITE = 7,
  EVENT_PTRACE = 8,
};

enum verdict {
  VERDICT_ALLOW = 0,
  VERDICT_BLOCK = 1,
  VERDICT_KILL = 2,
};

#endif
