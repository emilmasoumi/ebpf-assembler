/*
  Load C macro preprocessors defining the bytecode, stored in a composite type
  struct defined in `macros.h`.
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <linux/unistd.h>
#include <string.h>
#include <linux/filter.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/syscall.h>

#include "../headers/bpf_insn.h"
#include "macros.h"

#ifndef __NR_BPF
#define __NR_BPF 321
#endif
#define ptr_to_u64(ptr) ((__u64)(unsigned long)(ptr))

#define LOG_BUF_SIZE 65535
#define MAX_INSNS 1000000
char bpf_log_buf[LOG_BUF_SIZE];

static int bpf_create_map(enum bpf_map_type map_type,
                          int               key_size,
                          int               value_size,
                          int               max_entries) {

  union bpf_attr attr = {
    .map_type    = map_type,
    .key_size    = key_size,
    .value_size  = value_size,
    .max_entries = max_entries
  };
  return syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
}

static int bpf_prog_load(enum bpf_prog_type     prog_type,
                         const struct bpf_insn* insns,
                         int                    prog_len,
                         const char*            license) {
  union bpf_attr attr = {
    .prog_type = prog_type,
    .insns     = ptr_to_u64(insns),
    .insn_cnt  = prog_len / sizeof(struct bpf_insn),
    .license   = ptr_to_u64(license),
    .log_buf   = ptr_to_u64(bpf_log_buf),
    .log_size  = LOG_BUF_SIZE,
    .log_level = 1,
    };

  bpf_log_buf[0] = 0;

  return syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
}

static int probe_filter_length(struct bpf_insn *fp) {
  int len = 0;

  for (len = MAX_INSNS - 1; len > 0; --len)
    if (fp[len].code != 0 || fp[len].imm != 0)
      break;

  return len + 1;
}

int main(void) {
  int map_fd, prog_len;
  map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(int),
                          sizeof(long long),  1024);
  map_fd   = map_fd;
  prog_len = probe_filter_length(prog);

  int prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, prog,
                              prog_len * sizeof(struct bpf_insn), "GPL");

  if (prog_fd < 0) {
    printf("%s\n", bpf_log_buf);
    fprintf(stderr, "failed to load object code: %s\n", strerror(errno));
  } else {
    printf("%s\n", bpf_log_buf);
    printf("eBPF program load was successful.\n");
  }

  return 0;
}
