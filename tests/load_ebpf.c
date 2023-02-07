/*
  Load eBPF bytecode into the kernel, from a file containing the object code.
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/syscall.h>

#include "../headers/bpf_insn.h"

#ifndef __NR_BPF
#define __NR_BPF 321
#endif
#define ptr_to_u64(ptr) ((__u64)(unsigned long)(ptr))

#define MAX_INSNS 1000000
#define LOG_BUF_SIZE 1048576

char ebpf_log_buf[LOG_BUF_SIZE];

int bpf_prog_load(enum bpf_prog_type     prog_type,
                  const struct bpf_insn* insns,
                  int                    prog_len,
                  const char*            license) {
  union bpf_attr attr = {
    .prog_type = prog_type,
    .insns     = ptr_to_u64((void*)insns),
    .insn_cnt  = prog_len / sizeof(struct bpf_insn),
    .license   = ptr_to_u64((void*)license),
    .log_buf   = ptr_to_u64(ebpf_log_buf),
    .log_size  = LOG_BUF_SIZE,
    .log_level = 1,
  };

  ebpf_log_buf[0] = 0;

  return syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
}

int bpf_create_map(enum bpf_map_type map_type,
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

static int create_map(void) {
  long long key, value = 0;
  int map_fd;

  map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(key), sizeof(value), 1024);
  if (map_fd < 0) {
    printf("Failed to create map: %s\n", strerror(errno));
    exit(1);
  }

  return map_fd;
}

int main(int    argc,
         char** argv) {
  if (argc != 2) {
    printf("%s: error: no eBPF object code provided\n", *argv);
    printf("usage: %s <file-with-object-code>\n", *argv);
    return 1;
  }

  char* fname = *++argv;

  int fd;
  fd = open(fname, O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "error: open() failed opening ``%s``: %s",
            *argv, strerror(errno));
    return 1;
  }

  // Get the amount of bytes in the object code.
  size_t size;
  struct stat st;
  if (stat(fname, &st) < 0) {
    fprintf(stderr, "error: stat() failed: %s\n", strerror(errno));
    return 1;
  }
  size = st.st_size;

  uint8_t* objcode = (uint8_t*)malloc(size*sizeof(uint8_t));
  if (objcode == NULL) {
    fprintf(stderr, "error: malloc() failed: %s\n", strerror(errno));
    return 1;
  }

  ssize_t rd = read(fd, objcode, size);
  if (rd < 0) {
    fprintf(stderr, "error: read() failed with error code description: %s",
            strerror(errno));
    return 1;
  }
  close(fd);

  int prog_len;
  prog_len = size / sizeof(struct bpf_insn);

  struct bpf_insn *prog, *insn;

  /* Create an eBPF map if any instructions in the bytecode use it. */
  prog = malloc(size);
  if (prog == NULL) {
    fprintf(stderr, "error: malloc() failed: %s\n", strerror(errno));
    return 1;
  }
  memcpy(prog, objcode, size);
  insn = prog;
  for (int i = 0; i < prog_len; i++, insn++) {
    if ((insn[0].code == (BPF_LD | BPF_IMM | BPF_DW)) &&
        insn->src_reg == BPF_PSEUDO_MAP_FD) {
      int map_fd = create_map();
      insn->imm  = map_fd;
    }
  }

  int prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, prog,
                              prog_len * sizeof(struct bpf_insn), "GPL");
  if (prog_fd < 0) {
    printf("%s\n", ebpf_log_buf);
    fprintf(stderr, "failed to load object code: %s\n", strerror(errno));
  } else {
    printf("%s\n", ebpf_log_buf);
    printf("eBPF program load was successful.\n");
  }

  free(objcode);
  free(prog);

  return 0;
}
