/*
  It is expected that the project has been build, and that the assembler is
  located in the parent directory with respect to the executable `tests` file.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <math.h>

#include "../headers/bpf_insn.h"
#include "tests.h"

#define CRED "\x1B[1;31m"
#define CNRM "\x1B[0m"

int err(char* fmt, ...) {
  va_list args;

  va_start(args, fmt);
  fputs("error: ", stderr);
  vfprintf(stderr, fmt, args);
  va_end(args);

  return 0;
}

int delete_file(char* pname) {
  if (access(pname, F_OK) != 0)
    return 1;
  if (remove(pname))
    return err("remove(%s) failed: %s\n", pname, strerror(errno));
  return 1;
}

int assert_true(char*            pname,
                struct bpf_insn* insns,
                size_t           test_size) {
  char cmd[64];
  snprintf(cmd, sizeof(cmd), "../ebpf-as %s.s", pname);

  if (system(cmd))
    return err("system(%s) failed: %s\n", cmd, strerror(errno));

  int fd;
  fd = open(pname, O_RDONLY);
  if (fd < 0)
    return err("open(%s) failed: %s\n", pname, strerror(errno));

  size_t size;
  struct stat st;
  if (stat(pname, &st) < 0)
    return err("stat() failed: %s\n", strerror(errno));
  size = st.st_size;

  uint8_t* prog = (uint8_t*)malloc(size);
  if (prog == NULL)
    return err("malloc() failed: %s\n", strerror(errno));

  if (read(fd, prog, size) < 0) {
    free(prog);
    return err("read() failed: %s\n", strerror(errno));
  }
  close(fd);

  if (size != sizeof(insns)*test_size) {
    printf("assertion failed: object codes are of unequal sizes: %lu != %lu\n",
           size, sizeof(insns)*test_size);
    free(prog);
    return 0;
  }

  const uint8_t* const objcode = (const uint8_t*) insns;

  for (size_t i=0; i<size; ++i) {
    if (objcode[i] != prog[i]) {
      printf("%s: assertion failed: insns[%zu - 1]: %hhu != %hhu\n",
             pname, (size_t)floor((i/8)+1), objcode[i], prog[i]);
      free(prog);
      return 0;
    }
  }

  free(prog);

  return 1;
}

int assert_false(char* pname) {
  char cmd[64];
  snprintf(cmd, sizeof(cmd), "../ebpf-as %s.s > /dev/null 2>&1", pname);

  // Any error is a good error.
  if (system(cmd))
    return 1;

  return 0;
}

int test(char*            pname,
         struct bpf_insn* insns,
         size_t           test_size,
         size_t*          succ,
         bool             t) {
  if (t) {
    if (assert_true(pname, insns, test_size))
      (*succ)++;
    else
      printf("Test: %s %sfailed%s^^^\n", pname, CRED, CNRM);
    delete_file(pname);
  }
  else {
    if (assert_false(pname))
      (*succ)++;
    else {
      printf("Test: %s %sfailed%s^^^\n", pname, CRED, CNRM);
      delete_file(pname);
    }
  }
  return 1;
}

int main() {
  size_t succ = 0;

  test("./input/true/test1",   test1,   TEST1_SIZE,   &succ, true);
  test("./input/true/test2",   test2,   TEST2_SIZE,   &succ, true);
  test("./input/true/test3",   test3,   TEST3_SIZE,   &succ, true);
  test("./input/true/test4",   test4,   TEST4_SIZE,   &succ, true);
  test("./input/true/test5",   test5,   TEST5_SIZE,   &succ, true);
  test("./input/true/test6",   test6,   TEST6_SIZE,   &succ, true);
  test("./input/true/test7",   test7,   TEST7_SIZE,   &succ, true);
  test("./input/true/test8",   test8,   TEST8_SIZE,   &succ, true);
  test("./input/true/test9",   test9,   TEST9_SIZE,   &succ, true);
  test("./input/true/test10",  test10,  TEST10_SIZE,  &succ, true);
  test("./input/true/test11",  test11,  TEST11_SIZE,  &succ, true);
  test("./input/true/test12",  test12,  TEST12_SIZE,  &succ, true);
  test("./input/true/test13",  test13,  TEST13_SIZE,  &succ, true);
  test("./input/true/test14",  test14,  TEST14_SIZE,  &succ, true);
  test("./input/true/test15",  test15,  TEST15_SIZE,  &succ, true);
  test("./input/true/test16",  test16,  TEST16_SIZE,  &succ, true);
  test("./input/true/test17",  test17,  TEST17_SIZE,  &succ, true);
  test("./input/true/test18",  test18,  TEST18_SIZE,  &succ, true);
  test("./input/true/test19",  test19,  TEST19_SIZE,  &succ, true);
  test("./input/true/test20",  test20,  TEST20_SIZE,  &succ, true);
  test("./input/true/test21",  test21,  TEST21_SIZE,  &succ, true);
  test("./input/true/test22",  test22,  TEST22_SIZE,  &succ, true);
  test("./input/true/test23",  test23,  TEST23_SIZE,  &succ, true);
  test("./input/true/test100", test100, TEST100_SIZE, &succ, true);
  test("./input/true/test101", test101, TEST101_SIZE, &succ, true);
  test("./input/true/test102", test102, TEST102_SIZE, &succ, true);
  test("./input/true/test103", test103, TEST103_SIZE, &succ, true);
  test("./input/true/test104", test104, TEST104_SIZE, &succ, true);
  test("./input/true/test105", test105, TEST105_SIZE, &succ, true);
  test("./input/true/test106", test106, TEST106_SIZE, &succ, true);
  test("./input/true/test107", test107, TEST107_SIZE, &succ, true);
  test("./input/true/test108", test108, TEST108_SIZE, &succ, true);
  test("./input/true/test109", test109, TEST109_SIZE, &succ, true);


  char pname[64];

  for (size_t i=1; i<NUM_FALSE_TESTS+1; ++i) {
    snprintf(pname, sizeof(pname), "./input/false/test%zu", i);
    test(pname, NULL, 0, &succ, false);
    memset(pname, 0, 64);
  }

  printf("%zu/%zu tests succeeded.\n", succ, (size_t)NUM_TESTS);

  return 0;
}
