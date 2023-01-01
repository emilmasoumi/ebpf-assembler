/*
  Disassembles eBPF object code to eBPF bytecode.
*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "../headers/bpf_insn.h"

static inline short byte_concat_bits(unsigned char x, unsigned char y) {
  return (x << 8) | y;
}

static inline int short_concat_bits(short x, short y) {
  return (x << 16) | y;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    printf("%s: error: no eBPF object code provided\n", *argv);
    printf("usage: %s <file-with-object-code>\n", *argv);
    return 1;
  }

  char* fname = *++argv;

  int fd;
  fd = open(fname, O_RDONLY);

  if (fd < 0) {
    fprintf(stderr, "error: fopen() failed opening ``%s``: %s\n",
            *argv, strerror(errno));
    return 1;
  }

  // Get the amount of bytes in the object code.
  long int size;
  struct stat st;
  if (stat(fname, &st) < 0) {
    fprintf(stderr, "error: stat() failed: %s\n", strerror(errno));
    return 1;
  }
  size = st.st_size;

  unsigned char *objcode =
    (unsigned char*)malloc(size*sizeof(unsigned char));

  ssize_t rd = read(fd, objcode, size);
  if (rd < 0) {
    fprintf(stderr, "error: read() failed with error code description: %s\n",
            strerror(errno));
    return 1;
  }
  close(fd);

  if (size < 1 || ((size) % 8)) {
    printf("error: the object code has a distorted encoding size\n");
    return 1;
  }

  // struct bpf_insn linux/include/uapi/linux/bpf.h
  __u8 opcode;  /* opcode */
  __u8 dst_reg; /* dest register */
  __u8 src_reg; /* source register */
  __s16 off;    /* signed offset */
  __s32 imm;    /* signed immediate constant */

  int addr = 0x00000;
  for (int i=7; i<size; i+=8) {
    addr++;
    opcode  = objcode[i-7];
    dst_reg = objcode[i-6] & 0xf;
    src_reg = (objcode[i-6]>>4) & 0xf;
    off     = byte_concat_bits(objcode[i-4], objcode[i-5]);
    imm     = short_concat_bits(byte_concat_bits(objcode[i], objcode[i-1]),
                                byte_concat_bits(objcode[i-2], objcode[i-3]));

    printf("%05x: ", addr);

    /*
      ALU64 DST_REG SRC_REG
    */
    /* BPF_ALU64_REG */
    // add dst src
    if (opcode == (BPF_ALU64 | BPF_OP(BPF_ADD) | BPF_X))
      printf("add r%d r%d", dst_reg, src_reg);
    // sub dst src
    else if (opcode == (BPF_ALU64 | BPF_OP(BPF_SUB) | BPF_X))
      printf("sub r%d r%d", dst_reg, src_reg);
    // mul dst src
    else if (opcode == (BPF_ALU64 | BPF_OP(BPF_MUL) | BPF_X))
      printf("mul r%d r%d", dst_reg, src_reg);
    // div dst src
    else if (opcode == (BPF_ALU64 | BPF_OP(BPF_DIV) | BPF_X))
      printf("div r%d r%d", dst_reg, src_reg);
    // or dst src
    else if (opcode == (BPF_ALU64 | BPF_OP(BPF_OR) | BPF_X))
      printf("or r%d r%d", dst_reg, src_reg);
    // and dst src
    else if (opcode == (BPF_ALU64 | BPF_OP(BPF_AND) | BPF_X))
      printf("and r%d r%d", dst_reg, src_reg);
    // lsh dst src
    else if (opcode == (BPF_ALU64 | BPF_OP(BPF_LSH) | BPF_X))
      printf("lsh r%d r%d", dst_reg, src_reg);
    // rsh dst src
    else if (opcode == (BPF_ALU64 | BPF_OP(BPF_RSH) | BPF_X))
      printf("rsh r%d r%d", dst_reg, src_reg);
    // neg DST_REG
    else if (opcode == (BPF_ALU64 | BPF_OP(BPF_AND) | BPF_X))
      printf("neg r%d", dst_reg);
    // mod dst src
    else if (opcode == (BPF_ALU64 | BPF_OP(BPF_MOD) | BPF_X))
      printf("mod r%d r%d", dst_reg, src_reg);
    // xor dst src
    else if (opcode == (BPF_ALU64 | BPF_OP(BPF_XOR) | BPF_X))
      printf("xor r%d r%d", dst_reg, src_reg);
    // mov dst src
    else if (opcode == (BPF_ALU64 | BPF_OP(BPF_MOV) | BPF_X))
      printf("mov r%d r%d", dst_reg, src_reg);
    // arsh dst src
    else if (opcode == (BPF_ALU64 | BPF_OP(BPF_ARSH) | BPF_X))
      printf("arsh r%d r%d", dst_reg, src_reg);

    /*
      ALU64 DST_REG IMM
    */
    /* BPF_ALU64_IMM */
    // add dst imm
    else if (opcode == (BPF_ALU64 | BPF_OP(BPF_ADD) | BPF_K))
      printf("add r%d %d", dst_reg, imm);
    // sub dst imm
    else if (opcode == (BPF_ALU64 | BPF_OP(BPF_SUB) | BPF_K))
      printf("sub r%d %d", dst_reg, imm);
    // mul dst imm
    else if (opcode == (BPF_ALU64 | BPF_OP(BPF_MUL) | BPF_K))
      printf("mul r%d %d", dst_reg, imm);
    // div dst imm
    else if (opcode == (BPF_ALU64 | BPF_OP(BPF_DIV) | BPF_K))
      printf("div r%d %d", dst_reg, imm);
    // or dst imm
    else if (opcode == (BPF_ALU64 | BPF_OP(BPF_OR) | BPF_K))
      printf("or r%d %d", dst_reg, imm);
    // and dst imm
    else if (opcode == (BPF_ALU64 | BPF_OP(BPF_AND) | BPF_K))
      printf("and r%d %d", dst_reg, imm);
    // lsh dst imm
    else if (opcode == (BPF_ALU64 | BPF_OP(BPF_LSH) | BPF_K))
      printf("lsh r%d %d", dst_reg, imm);
    // rsh dst imm
    else if (opcode == (BPF_ALU64 | BPF_OP(BPF_RSH) | BPF_K))
      printf("rsh r%d %d", dst_reg, imm);
    // mod dst imm
    else if (opcode == (BPF_ALU64 | BPF_OP(BPF_MOD) | BPF_K))
      printf("mod r%d %d", dst_reg, imm);
    // xor dst imm
    else if (opcode == (BPF_ALU64 | BPF_OP(BPF_XOR) | BPF_K))
      printf("xor r%d %d", dst_reg, imm);
    // mov dst imm
    else if (opcode == (BPF_ALU64 | BPF_OP(BPF_MOV) | BPF_K))
      printf("mov r%d %d", dst_reg, imm);
    // arsh dst imm
    else if (opcode == (BPF_ALU64 | BPF_OP(BPF_ARSH) | BPF_K))
      printf("arsh r%d %d", dst_reg, imm);

    /*
      ALU32 DST_REG SRC_REG
    */
    /* BPF_ALU32_REG */
    // add32 dst src
    else if (opcode == (BPF_ALU | BPF_OP(BPF_ADD) | BPF_X))
      printf("add32 r%d r%d", dst_reg, src_reg);
    // sub32 dst src
    else if (opcode == (BPF_ALU | BPF_OP(BPF_SUB) | BPF_X))
      printf("sub32 r%d r%d", dst_reg, src_reg);
    // mul32 dst src
    else if (opcode == (BPF_ALU | BPF_OP(BPF_MUL) | BPF_X))
      printf("mul32 r%d r%d", dst_reg, src_reg);
    // div32 dst src
    else if (opcode == (BPF_ALU | BPF_OP(BPF_DIV) | BPF_X))
      printf("div32 r%d r%d", dst_reg, src_reg);
    // or32 dst src
    else if (opcode == (BPF_ALU | BPF_OP(BPF_OR) | BPF_X))
      printf("or32 r%d r%d", dst_reg, src_reg);
    // and32 dst src
    else if (opcode == (BPF_ALU | BPF_OP(BPF_AND) | BPF_X))
      printf("and32 r%d r%d", dst_reg, src_reg);
    // lsh32 dst src
    else if (opcode == (BPF_ALU | BPF_OP(BPF_LSH) | BPF_X))
      printf("lsh32 r%d r%d", dst_reg, src_reg);
    // rsh32 dst src
    else if (opcode == (BPF_ALU | BPF_OP(BPF_RSH) | BPF_X))
      printf("rsh32 r%d r%d", dst_reg, src_reg);
    // neg32 DST_REG
    else if (opcode == (BPF_ALU | BPF_OP(BPF_AND) | BPF_X))
      printf("neg32 r%d", dst_reg);
    // mod32 dst src
    else if (opcode == (BPF_ALU | BPF_OP(BPF_MOD) | BPF_X))
      printf("mod32 r%d r%d", dst_reg, src_reg);
    // xor32 dst src
    else if (opcode == (BPF_ALU | BPF_OP(BPF_XOR) | BPF_X))
      printf("xor32 r%d r%d", dst_reg, src_reg);
    // mov32 dst src
    else if (opcode == (BPF_ALU | BPF_OP(BPF_MOV) | BPF_X)  && imm != 1)
      printf("mov32 r%d r%d", dst_reg, src_reg);
    // arsh32 dst src
    else if (opcode == (BPF_ALU | BPF_OP(BPF_ARSH) | BPF_X))
      printf("arsh32 r%d r%d", dst_reg, src_reg);

    /*
      ALU32 DST_REG IMM
    */
    /* BPF_ALU32_IMM */
    // add dst imm
    else if (opcode == (BPF_ALU | BPF_OP(BPF_ADD) | BPF_K))
      printf("add32 r%d %d", dst_reg, imm);
    // sub dst imm
    else if (opcode == (BPF_ALU | BPF_OP(BPF_SUB) | BPF_K))
      printf("sub32 r%d %d", dst_reg, imm);
    // mul dst imm
    else if (opcode == (BPF_ALU | BPF_OP(BPF_MUL) | BPF_K))
      printf("mul32 r%d %d", dst_reg, imm);
    // div dst imm
    else if (opcode == (BPF_ALU | BPF_OP(BPF_DIV) | BPF_K))
      printf("div32 r%d %d", dst_reg, imm);
    // or dst imm
    else if (opcode == (BPF_ALU | BPF_OP(BPF_OR) | BPF_K))
      printf("or32 r%d %d", dst_reg, imm);
    // and dst imm
    else if (opcode == (BPF_ALU | BPF_OP(BPF_AND) | BPF_K))
      printf("and32 r%d %d", dst_reg, imm);
    // lsh dst imm
    else if (opcode == (BPF_ALU | BPF_OP(BPF_LSH) | BPF_K))
      printf("lsh32 r%d %d", dst_reg, imm);
    // rsh dst imm
    else if (opcode == (BPF_ALU | BPF_OP(BPF_RSH) | BPF_K))
      printf("rsh32 r%d %d", dst_reg, imm);
    // mod dst imm
    else if (opcode == (BPF_ALU | BPF_OP(BPF_MOD) | BPF_K))
      printf("mod32 r%d %d", dst_reg, imm);
    // xor dst imm
    else if (opcode == (BPF_ALU | BPF_OP(BPF_XOR) | BPF_K))
      printf("xor32 r%d %d", dst_reg, imm);
    // mov dst imm
    else if (opcode == (BPF_ALU | BPF_OP(BPF_MOV) | BPF_K))
      printf("mov32 r%d %d", dst_reg, imm);
    // arsh dst imm
    else if (opcode == (BPF_ALU | BPF_OP(BPF_ARSH) | BPF_K))
      printf("arsh32 r%d %d", dst_reg, imm);

    /*
      Endianess conversion (Byteswap) DST_REG | DST_REG = f(DST_REG)
    */
    /* BPF_ENDIAN */
    // le dst
    else if (opcode == (BPF_ALU | BPF_END | BPF_SRC(BPF_TO_LE)))
      printf("le%d r%d", imm, dst_reg);
    // be dst
    else if (opcode == (BPF_ALU | BPF_END | BPF_SRC(BPF_TO_BE)))
      printf("be%d r%d", imm, dst_reg);

    /*
      Atomic operations - TBA ~ kernel version 5.12+
    */
    /* BPF_ATOMIC_OP */
    // addx16 dst src off
    else if (opcode == (BPF_STX | BPF_SIZE(16) | BPF_ATOMIC) &&
             imm == BPF_ADD)
      printf("addx16 r%d r%d %d", dst_reg, src_reg, off);
    // addx32 dst src off
    else if (opcode == (BPF_STX | BPF_SIZE(32) | BPF_ATOMIC) &&
             imm == BPF_ADD)
      printf("addx32 r%d r%d %d", dst_reg, src_reg, off);
    // addx64 dst src off
    else if (opcode == (BPF_STX | BPF_SIZE(64) | BPF_ATOMIC) &&
             imm == BPF_ADD)
      printf("addx64 r%d r%d %d", dst_reg, src_reg, off);
    // andx16 dst src off
    else if (opcode == (BPF_STX | BPF_SIZE(16) | BPF_ATOMIC) &&
             imm == BPF_AND)
      printf("andx16 r%d r%d %d", dst_reg, src_reg, off);
    // andx32 dst src off
    else if (opcode == (BPF_STX | BPF_SIZE(32) | BPF_ATOMIC) &&
             imm == BPF_AND)
      printf("andx32 r%d r%d %d", dst_reg, src_reg, off);
    // andx64 dst src off
    else if (opcode == (BPF_STX | BPF_SIZE(64) | BPF_ATOMIC) &&
             imm == BPF_AND)
      printf("andx64 r%d r%d %d", dst_reg, src_reg, off);
    // orx16 dst src off
    else if (opcode == (BPF_STX | BPF_SIZE(16) | BPF_ATOMIC) &&
             imm == BPF_OR)
      printf("orx16 r%d r%d %d", dst_reg, src_reg, off);
    // orx32 dst src off
    else if (opcode == (BPF_STX | BPF_SIZE(32) | BPF_ATOMIC) &&
             imm == BPF_OR)
      printf("orx32 r%d r%d %d", dst_reg, src_reg, off);
    // orx64 dst src off
    else if (opcode == (BPF_STX | BPF_SIZE(64) | BPF_ATOMIC) &&
             imm == BPF_OR)
      printf("orx64 r%d r%d %d", dst_reg, src_reg, off);
    // xorx16 dst src off
    else if (opcode == (BPF_STX | BPF_SIZE(16) | BPF_ATOMIC) &&
             imm == BPF_XOR)
      printf("xorx16 r%d r%d %d", dst_reg, src_reg, off);
    // xorx32 dst src off
    else if (opcode == (BPF_STX | BPF_SIZE(32) | BPF_ATOMIC) &&
             imm == BPF_XOR)
      printf("xorx32 r%d r%d %d", dst_reg, src_reg, off);
    // xorx64 dst src off
    else if (opcode == (BPF_STX | BPF_SIZE(64) | BPF_ATOMIC) &&
             imm == BPF_XOR)
      printf("xorx64 r%d r%d %d", dst_reg, src_reg, off);
    // addfx16 dst src off
    else if (opcode == (BPF_STX | BPF_SIZE(16) | BPF_ATOMIC) &&
             imm == (BPF_ADD | BPF_FETCH))
      printf("addfx16 r%d r%d %d", dst_reg, src_reg, off);
    // addfx32 dst src off
    else if (opcode == (BPF_STX | BPF_SIZE(32) | BPF_ATOMIC) &&
             imm == (BPF_ADD | BPF_FETCH))
      printf("addfx32 r%d r%d %d", dst_reg, src_reg, off);
    // addfx64 dst src off
    else if (opcode == (BPF_STX | BPF_SIZE(64) | BPF_ATOMIC) &&
             imm == (BPF_ADD | BPF_FETCH))
      printf("addfx64 r%d r%d %d", dst_reg, src_reg, off);
    // andfx16 dst src off
    else if (opcode == (BPF_STX | BPF_SIZE(16) | BPF_ATOMIC) &&
             imm == (BPF_AND | BPF_FETCH))
      printf("andfx16 r%d r%d %d", dst_reg, src_reg, off);
    // andfx32 dst src off
    else if (opcode == (BPF_STX | BPF_SIZE(32) | BPF_ATOMIC) &&
             imm == (BPF_AND | BPF_FETCH))
      printf("andfx32 r%d r%d %d", dst_reg, src_reg, off);
    // andfx64 dst src off
    else if (opcode == (BPF_STX | BPF_SIZE(64) | BPF_ATOMIC) &&
             imm == (BPF_AND | BPF_FETCH))
      printf("andfx64 r%d r%d %d", dst_reg, src_reg, off);
    // orfx16 dst src off
    else if (opcode == (BPF_STX | BPF_SIZE(16) | BPF_ATOMIC) &&
             imm == (BPF_OR | BPF_FETCH))
      printf("orfx16 r%d r%d %d", dst_reg, src_reg, off);
    // orfx32 dst src off
    else if (opcode == (BPF_STX | BPF_SIZE(32) | BPF_ATOMIC) &&
             imm == (BPF_OR | BPF_FETCH))
      printf("orfx32 r%d r%d %d", dst_reg, src_reg, off);
    // orfx64 dst src off
    else if (opcode == (BPF_STX | BPF_SIZE(64) | BPF_ATOMIC) &&
             imm == (BPF_OR | BPF_FETCH))
      printf("orfx64 r%d r%d %d", dst_reg, src_reg, off);
    // xorfx16 dst src off
    else if (opcode == (BPF_STX | BPF_SIZE(16) | BPF_ATOMIC) &&
             imm == (BPF_XOR | BPF_FETCH))
      printf("xorfx16 r%d r%d %d", dst_reg, src_reg, off);
    // xorfx32 dst src off
    else if (opcode == (BPF_STX | BPF_SIZE(32) | BPF_ATOMIC) &&
             imm == (BPF_XOR | BPF_FETCH))
      printf("xorfx32 r%d r%d %d", dst_reg, src_reg, off);
    // xorfx64 dst src off
    else if (opcode == (BPF_STX | BPF_SIZE(64) | BPF_ATOMIC) &&
             imm == (BPF_XOR | BPF_FETCH))
      printf("xorfx64 r%d r%d %d", dst_reg, src_reg, off);
    // xchgx16 dst src off
    else if (opcode == (BPF_STX | BPF_SIZE(16) | BPF_ATOMIC) &&
             imm == BPF_XCHG)
      printf("xchgx16 r%d r%d %d", dst_reg, src_reg, off);
    // xchgx32 dst src off
    else if (opcode == (BPF_STX | BPF_SIZE(32) | BPF_ATOMIC) &&
             imm == BPF_XCHG)
      printf("xchgx32 r%d r%d %d", dst_reg, src_reg, off);
    // xchgx64 dst src off
    else if (opcode == (BPF_STX | BPF_SIZE(64) | BPF_ATOMIC) &&
             imm == BPF_XCHG)
      printf("xchgx64 r%d r%d %d", dst_reg, src_reg, off);
    // cmpxchgx16 dst src off
    else if (opcode == (BPF_STX | BPF_SIZE(16) | BPF_ATOMIC) &&
             imm == BPF_CMPXCHG)
      printf("cmpxchgx16 r%d r%d %d", dst_reg, src_reg, off);
    // cmpxchgx32 dst src off
    else if (opcode == (BPF_STX | BPF_SIZE(32) | BPF_ATOMIC) &&
             imm == BPF_CMPXCHG)
      printf("cmpxchgx32 r%d r%d %d", dst_reg, src_reg, off);
    // cmpxchgx64 dst src off
    else if (opcode == (BPF_STX | BPF_SIZE(64) | BPF_ATOMIC) &&
             imm == BPF_CMPXCHG)
      printf("cmpxchgx64 r%d r%d %d", dst_reg, src_reg, off);

    /*
      Memory instructions
    */

    /* BPF_LD_MAP_FD */
    else if (opcode == (BPF_LD | BPF_DW | BPF_IMM) &&
             src_reg == BPF_PSEUDO_MAP_FD)
      printf("ldmapfd r%d %d", dst_reg, imm);
    /* BPF_LD_IMM64 */
    else if (opcode == (BPF_LD | BPF_DW | BPF_IMM))
      printf("ld64 r%d %d", dst_reg, imm);

    /* BPF_LD_ABS */
    else if (opcode == (BPF_LD | BPF_SIZE(8) | BPF_ABS))
      printf("ldabs8 %d", imm);
    else if (opcode == (BPF_LD | BPF_SIZE(16) | BPF_ABS))
      printf("ldabs16 %d", imm);
    else if (opcode == (BPF_LD | BPF_SIZE(32) | BPF_ABS))
      printf("ldabs32 %d", imm);
    else if (opcode == (BPF_LD | BPF_SIZE(64) | BPF_ABS))
      printf("ldabs64 %d", imm);

    /* BPF_LD_IND */
    else if (opcode == (BPF_LD | BPF_SIZE(8) | BPF_IND))
      printf("ldind8 r%d %d", src_reg, imm);
    else if (opcode == (BPF_LD | BPF_SIZE(16) | BPF_IND))
      printf("ldind16 r%d %d", src_reg, imm);
    else if (opcode == (BPF_LD | BPF_SIZE(32) | BPF_IND))
      printf("ldind32 r%d %d", src_reg, imm);
    else if (opcode == (BPF_LD | BPF_SIZE(64) | BPF_IND))
      printf("ldind64 r%d %d", src_reg, imm);

    /* BPF_LDX_MEM */
    else if (opcode == (BPF_LDX | BPF_SIZE(8) | BPF_MEM))
      printf("ldx8 r%d r%d %d", dst_reg, src_reg, off);
    else if (opcode == (BPF_LDX | BPF_SIZE(16) | BPF_MEM))
      printf("ldx16 r%d r%d %d", dst_reg, src_reg, off);
    else if (opcode == (BPF_LDX | BPF_SIZE(32) | BPF_MEM))
      printf("ldx32 r%d r%d %d", dst_reg, src_reg, off);
    else if (opcode == (BPF_LDX | BPF_SIZE(64) | BPF_MEM))
      printf("ldx64 r%d r%d %d", dst_reg, src_reg, off);

    /* BPF_ST_MEM */
    else if (opcode == (BPF_ST | BPF_SIZE(8) | BPF_MEM))
      printf("st8 r%d %d %d", dst_reg, off, imm);
    else if (opcode == (BPF_ST | BPF_SIZE(16) | BPF_MEM))
      printf("st16 r%d %d %d", dst_reg, off, imm);
    else if (opcode == (BPF_ST | BPF_SIZE(32) | BPF_MEM))
      printf("st32 r%d %d %d", dst_reg, off, imm);
    else if (opcode == (BPF_ST | BPF_SIZE(64) | BPF_MEM))
      printf("st64 r%d %d %d", dst_reg, off, imm);

    /* BPF_STX_MEM */
    else if (opcode == (BPF_STX | BPF_SIZE(8) | BPF_MEM))
      printf("stx8 r%d r%d %d", dst_reg, src_reg, off);
    else if (opcode == (BPF_STX | BPF_SIZE(16) | BPF_MEM))
      printf("stx8 r%d r%d %d", dst_reg, src_reg, off);
    else if (opcode == (BPF_STX | BPF_SIZE(32) | BPF_MEM))
      printf("stx8 r%d r%d %d", dst_reg, src_reg, off);
    else if (opcode == (BPF_STX | BPF_SIZE(64) | BPF_MEM))
      printf("stx8 r%d r%d %d", dst_reg, src_reg, off);

    /* BPF_STX_XADD */
    else if (opcode == (BPF_STX | BPF_SIZE(8) | BPF_XADD))
      printf("stxx8 r%d r%d %d", dst_reg, src_reg, off);
    else if (opcode == (BPF_STX | BPF_SIZE(16) | BPF_XADD))
      printf("stxx16 r%d r%d %d", dst_reg, src_reg, off);
    else if (opcode == (BPF_STX | BPF_SIZE(32) | BPF_XADD))
      printf("stxx32 r%d r%d %d", dst_reg, src_reg, off);
    else if (opcode == (BPF_STX | BPF_SIZE(64) | BPF_XADD))
      printf("stxx64 r%d r%d %d", dst_reg, src_reg, off);

    /*
      Branching instructions
    */
    /* BPF_JMP_A */
    // ja off
    else if (opcode == (BPF_JMP | BPF_JA))
      printf("ja %d", off);

    /* BPF_JMP_REG */
    // jeq dst src off
    else if (opcode == (BPF_JMP | BPF_OP(BPF_JEQ) | BPF_X))
      printf("jeq r%d r%d %d", dst_reg, src_reg, off);
    // jgt dst src off
    else if (opcode == (BPF_JMP | BPF_OP(BPF_JGT) | BPF_X))
      printf("jgt r%d r%d %d", dst_reg, src_reg, off);
    // jge dst src off
    else if (opcode == (BPF_JMP | BPF_OP(BPF_JGE) | BPF_X))
      printf("jge r%d r%d %d", dst_reg, src_reg, off);
    // jlt dst src off
    else if (opcode == (BPF_JMP | BPF_OP(BPF_JLT) | BPF_X))
      printf("jlt r%d r%d %d", dst_reg, src_reg, off);
    // jle dst src off
    else if (opcode == (BPF_JMP | BPF_OP(BPF_JLE) | BPF_X))
      printf("jle r%d r%d %d", dst_reg, src_reg, off);
    // jset dst src off
    else if (opcode == (BPF_JMP | BPF_OP(BPF_JSET) | BPF_X))
      printf("jset r%d r%d %d", dst_reg, src_reg, off);
    // jne dst src off
    else if (opcode == (BPF_JMP | BPF_OP(BPF_JNE) | BPF_X))
      printf("jne r%d r%d %d", dst_reg, src_reg, off);
    // jsgt dst src off
    else if (opcode == (BPF_JMP | BPF_OP(BPF_JSGT) | BPF_X))
      printf("jsgt r%d r%d %d", dst_reg, src_reg, off);
    // jsge dst src off
    else if (opcode == (BPF_JMP | BPF_OP(BPF_JSGE) | BPF_X))
      printf("jsge r%d r%d %d", dst_reg, src_reg, off);
    // jslt dst src off
    else if (opcode == (BPF_JMP | BPF_OP(BPF_JSLT) | BPF_X))
      printf("jslt r%d r%d %d", dst_reg, src_reg, off);
    // jsle dst src off
    else if (opcode == (BPF_JMP | BPF_OP(BPF_JSLE) | BPF_X))
      printf("jsle r%d r%d %d", dst_reg, src_reg, off);

    /* BPF_JMP_IMM */
    // jeq dst imm OFF
    else if (opcode == (BPF_JMP | BPF_OP(BPF_JEQ) | BPF_K))
      printf("jeq r%d %d %d", dst_reg, imm, off);
    // jgt dst imm OFF
    else if (opcode == (BPF_JMP | BPF_OP(BPF_JGT) | BPF_K))
      printf("jgt r%d %d %d", dst_reg, imm, off);
    // jge dst imm OFF
    else if (opcode == (BPF_JMP | BPF_OP(BPF_JGE) | BPF_K))
      printf("jge r%d %d %d", dst_reg, imm, off);
    // jlt dst imm OFF
    else if (opcode == (BPF_JMP | BPF_OP(BPF_JLT) | BPF_K))
      printf("jlt r%d %d %d", dst_reg, imm, off);
    // jle dst imm OFF
    else if (opcode == (BPF_JMP | BPF_OP(BPF_JLE) | BPF_K))
      printf("jle r%d %d %d", dst_reg, imm, off);
    // jset dst imm OFF
    else if (opcode == (BPF_JMP | BPF_OP(BPF_JSET) | BPF_K))
      printf("jset r%d %d %d", dst_reg, imm, off);
    // jne dst imm OFF
    else if (opcode == (BPF_JMP | BPF_OP(BPF_JNE) | BPF_K))
      printf("jne r%d %d %d", dst_reg, imm, off);
    // jsgt dst imm OFF
    else if (opcode == (BPF_JMP | BPF_OP(BPF_JSGT) | BPF_K))
      printf("jsgt r%d %d %d", dst_reg, imm, off);
    // jsge dst imm OFF
    else if (opcode == (BPF_JMP | BPF_OP(BPF_JSGE) | BPF_K))
      printf("jsge r%d %d %d", dst_reg, imm, off);
    // jslt dst imm OFF
    else if (opcode == (BPF_JMP | BPF_OP(BPF_JSLT) | BPF_K))
      printf("jslt r%d %d %d", dst_reg, imm, off);
    // jsle dst imm OFF
    else if (opcode == (BPF_JMP | BPF_OP(BPF_JSLE) | BPF_K))
      printf("jsle r%d %d %d", dst_reg, imm, off);

    /* BPF_JMP32_REG */
    // jeq32 dst src off
    else if (opcode == (BPF_JMP32 | BPF_OP(BPF_JEQ) | BPF_X))
      printf("jeq32 r%d r%d %d", dst_reg, src_reg, off);
    // jgt32 dst src off
    else if (opcode == (BPF_JMP32 | BPF_OP(BPF_JGT) | BPF_X))
      printf("jgt32 r%d r%d %d", dst_reg, src_reg, off);
    // jge32 dst src off
    else if (opcode == (BPF_JMP32 | BPF_OP(BPF_JGE) | BPF_X))
      printf("jge32 r%d r%d %d", dst_reg, src_reg, off);
    // jlt32 dst src off
    else if (opcode == (BPF_JMP32 | BPF_OP(BPF_JLT) | BPF_X))
      printf("jlt32 r%d r%d %d", dst_reg, src_reg, off);
    // jle32 dst src off
    else if (opcode == (BPF_JMP32 | BPF_OP(BPF_JLE) | BPF_X))
      printf("jle32 r%d r%d %d", dst_reg, src_reg, off);
    // jset32 dst src off
    else if (opcode == (BPF_JMP32 | BPF_OP(BPF_JSET) | BPF_X))
      printf("jset32 r%d r%d %d", dst_reg, src_reg, off);
    // jne32 dst src off
    else if (opcode == (BPF_JMP32 | BPF_OP(BPF_JNE) | BPF_X))
      printf("jne32 r%d r%d %d", dst_reg, src_reg, off);
    // jsgt32 dst src off
    else if (opcode == (BPF_JMP32 | BPF_OP(BPF_JSGT) | BPF_X))
      printf("jsgt32 r%d r%d %d", dst_reg, src_reg, off);
    // jsge32 dst src off
    else if (opcode == (BPF_JMP32 | BPF_OP(BPF_JSGE) | BPF_X))
      printf("jsge32 r%d r%d %d", dst_reg, src_reg, off);
    // jslt32 dst src off
    else if (opcode == (BPF_JMP32 | BPF_OP(BPF_JSLT) | BPF_X))
      printf("jslt32 r%d r%d %d", dst_reg, src_reg, off);
    // jsle32 dst src off
    else if (opcode == (BPF_JMP32 | BPF_OP(BPF_JSLE) | BPF_X))
      printf("jsle32 r%d r%d %d", dst_reg, src_reg, off);

    /* BPF_JMP32_IMM */
    // jeq32 dst imm off
    else if (opcode == (BPF_JMP32 | BPF_OP(BPF_JEQ) | BPF_K))
      printf("jeq32 r%d %d %d", dst_reg, imm, off);
    // jgt32 dst imm off
    else if (opcode == (BPF_JMP32 | BPF_OP(BPF_JGT) | BPF_K))
      printf("jgt32 r%d %d %d", dst_reg, imm, off);
    // jge32 dst imm off
    else if (opcode == (BPF_JMP32 | BPF_OP(BPF_JGE) | BPF_K))
      printf("jge32 r%d %d %d", dst_reg, imm, off);
    // jlt32 dst imm off
    else if (opcode == (BPF_JMP32 | BPF_OP(BPF_JLT) | BPF_K))
      printf("jlt32 r%d %d %d", dst_reg, imm, off);
    // jle32 dst imm off
    else if (opcode == (BPF_JMP32 | BPF_OP(BPF_JLE) | BPF_K))
      printf("jle32 r%d %d %d", dst_reg, imm, off);
    // jset32 dst imm off
    else if (opcode == (BPF_JMP32 | BPF_OP(BPF_JSET) | BPF_K))
      printf("jset32 r%d %d %d", dst_reg, imm, off);
    // jne32 dst imm off
    else if (opcode == (BPF_JMP32 | BPF_OP(BPF_JNE) | BPF_K))
      printf("jne32 r%d %d %d", dst_reg, imm, off);
    // jsgt32 dst imm off
    else if (opcode == (BPF_JMP32 | BPF_OP(BPF_JSGT) | BPF_K))
      printf("jsgt32 r%d %d %d", dst_reg, imm, off);
    // jsge32 dst imm off
    else if (opcode == (BPF_JMP32 | BPF_OP(BPF_JSGE) | BPF_K))
      printf("jsge32 r%d %d %d", dst_reg, imm, off);
    // jslt32 dst imm off
    else if (opcode == (BPF_JMP32 | BPF_OP(BPF_JSLT) | BPF_K))
      printf("jslt32 r%d %d %d", dst_reg, imm, off);
    // jsle32 dst imm off
    else if (opcode == (BPF_JMP32 | BPF_OP(BPF_JSLE) | BPF_K))
      printf("jsle32 r%d %d %d", dst_reg, imm, off);

    /* BPF_CALL_REL */
    // rel imm
    else if (opcode == (BPF_JMP | BPF_CALL) && src_reg == BPF_PSEUDO_CALL)
      printf("rel %d", imm);
    /* BPF_EMIT_CALL */
    // call imm
    else if (opcode == (BPF_JMP | BPF_CALL))
      printf("call %d", imm);
    /* BPF_EXIT_INSN */
    // exit
    else if (opcode == (BPF_JMP | BPF_EXIT))
      printf("exit ");

    /*
      Special instructions
    */
    /* BPF_ZEXT_REG */
    // zext dst
    else if (opcode == (BPF_ALU | BPF_MOV | BPF_X) && imm == 1)
      printf("zext r%d", dst_reg);

    else
      printf("???? opcode=%x dst_reg=%d src_reg=%d off=%d imm=%d ????",
             opcode, dst_reg, src_reg, off, imm);
    printf("\n");


  }

  free(objcode);

  return 0;
}
