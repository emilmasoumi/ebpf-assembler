/* SPDX-License-Identifier: GPL-2.0 */
/* eBPF opcodes and bytecode as C macro preprocessors */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __BPF_INSN_H
#define __BPF_INSN_H

#include <stdbool.h>
#include <stdint.h>
#include <linux/bpf.h>

typedef  uint64_t u64;
typedef  int64_t  s64;

struct bpf_insn;

/* instruction classes */
#ifndef BPF_JMP32
#define BPF_JMP32 0x06  /* jmp mode in word width */
#endif
#ifndef BPF_ALU64
#define BPF_ALU64 0x07  /* alu mode in double word width */
#endif

#ifndef BPF_LD
#define BPF_LD 0x00
#endif
#ifndef BPF_LDX
#define BPF_LDX 0x01
#endif
#ifndef BPF_ST
#define BPF_ST 0x02
#endif
#ifndef BPF_STX
#define BPF_STX 0x03
#endif
#ifndef BPF_ALU
#define BPF_ALU 0x04
#endif
#ifndef BPF_JMP
#define BPF_JMP 0x05
#endif
#ifndef BPF_RET
#define BPF_RET 0x06
#endif
#ifndef BPF_MISC
#define BPF_MISC 0x07
#endif

/* ld/ldx fields */
#ifndef BPF_W
#define BPF_W 0x00 /* 32-bit */
#endif
#ifndef BPF_H
#define BPF_H 0x08 /* 16-bit */
#endif
#ifndef BPF_B
#define BPF_B 0x10 /*  8-bit */
#endif

/* eBPF    BPF_DW    0x18    64-bit */
#ifndef BPF_IMM
#define BPF_IMM 0x00
#endif
#ifndef BPF_ABS
#define BPF_ABS 0x20
#endif
#ifndef BPF_IND
#define BPF_IND 0x40
#endif
#ifndef BPF_MEM
#define BPF_MEM 0x60
#endif
#ifndef BPF_LEN
#define BPF_LEN 0x80
#endif
#ifndef BPF_MSH
#define BPF_MSH 0xa0
#endif

/* alu/jmp fields */
#ifndef BPF_ADD
#define BPF_ADD 0x00
#endif
#ifndef BPF_SUB
#define BPF_SUB 0x10
#endif
#ifndef BPF_MUL
#define BPF_MUL 0x20
#endif
#ifndef BPF_DIV
#define BPF_DIV 0x30
#endif
#ifndef BPF_OR
#define BPF_OR 0x40
#endif
#ifndef BPF_AND
#define BPF_AND 0x50
#endif
#ifndef BPF_LSH
#define BPF_LSH 0x60
#endif
#ifndef BPF_RSH
#define BPF_RSH 0x70
#endif
#ifndef BPF_NEG
#define BPF_NEG 0x80
#endif
#ifndef BPF_MOD
#define BPF_MOD 0x90
#endif
#ifndef BPF_XOR
#define BPF_XOR 0xa0
#endif

#ifndef BPF_JA
#define BPF_JA 0x00
#endif
#ifndef BPF_JEQ
#define BPF_JEQ 0x10
#endif
#ifndef BPF_JGT
#define BPF_JGT 0x20
#endif
#ifndef BPF_JGE
#define BPF_JGE 0x30
#endif
#ifndef BPF_JSET
#define BPF_JSET 0x40
#endif
#ifndef BPF_K
#define BPF_K 0x00
#endif
#ifndef BPF_X
#define BPF_X 0x08
#endif

/* ld/ldx fields */
#ifndef BPF_DW
#define BPF_DW 0x18  /* double word (64-bit) */
#endif
#ifndef BPF_XADD
#define BPF_XADD 0xc0  /* exclusive add */
#endif

/* alu/jmp fields */
#ifndef BPF_MOV
#define BPF_MOV 0xb0
#endif
#ifndef BPF_ARSH
#define BPF_ARSH 0xc0  /* sign extending arithmetic shift right */
#endif

/* change endianness of a register */
#ifndef BPF_END
#define BPF_END 0xd0  /* flags for endianness conversion: */
#endif
#ifndef BPF_TO_LE
#define BPF_TO_LE 0x00  /* convert to little-endian */
#endif
#ifndef BPF_TO_BE
#define BPF_TO_BE 0x08  /* convert to big-endian */
#endif
#ifndef BPF_FROM_LE
#define BPF_FROM_LE BPF_TO_LE
#endif
#ifndef BPF_FROM_BE
#define BPF_FROM_BE BPF_TO_BE
#endif

/* jmp encodings */
#ifndef BPF_JNE
#define BPF_JNE 0x50  /* jump != */
#endif
#ifndef BPF_JLT
#define BPF_JLT 0xa0  /* LT is unsigned, '<' */
#endif
#ifndef BPF_JLE
#define BPF_JLE 0xb0  /* LE is unsigned, '<=' */
#endif
#ifndef BPF_JSGT
#define BPF_JSGT 0x60  /* SGT is signed '>', GT in x86 */
#endif
#ifndef BPF_JSGE
#define BPF_JSGE 0x70  /* SGE is signed '>=', GE in x86 */
#endif
#ifndef BPF_JSLT
#define BPF_JSLT 0xc0  /* SLT is signed, '<' */
#endif
#ifndef BPF_JSLE
#define BPF_JSLE 0xd0  /* SLE is signed, '<=' */
#endif
#ifndef BPF_CALL
#define BPF_CALL 0x80  /* function call */
#endif
#ifndef BPF_EXIT
#define BPF_EXIT 0x90  /* function return */
#endif

#ifndef BPF_ATOMIC
#define BPF_ATOMIC 0xc0 /* atomic memory ops - op type in immediate */
#endif

/* atomic op type fields (stored in immediate) */
#ifndef BPF_FETCH
#define BPF_FETCH 0x01 /* not an opcode on its own, used to build others */
#endif
#ifndef BPF_XCHG
#define BPF_XCHG (0xe0 | BPF_FETCH) /* atomic exchange */
#endif
#ifndef BPF_CMPXCHG
#define BPF_CMPXCHG (0xf0 | BPF_FETCH) /* atomic compare-and-write */
#endif

/* ALU ops on registers, bpf_add|sub|...: dst_reg += src_reg */

#define BPF_ALU64_REG(OP, DST, SRC)           \
  ((struct bpf_insn) {                        \
    .code  = BPF_ALU64 | BPF_OP(OP) | BPF_X,  \
    .dst_reg = DST,                           \
    .src_reg = SRC,                           \
    .off   = 0,                               \
    .imm   = 0 })

#define BPF_ALU32_REG(OP, DST, SRC)        \
  ((struct bpf_insn) {                     \
    .code  = BPF_ALU | BPF_OP(OP) | BPF_X, \
    .dst_reg = DST,                        \
    .src_reg = SRC,                        \
    .off   = 0,                            \
    .imm   = 0 })

/* ALU ops on immediates, bpf_add|sub|...: dst_reg += imm32 */

#define BPF_ALU64_IMM(OP, DST, IMM)          \
  ((struct bpf_insn) {                       \
    .code  = BPF_ALU64 | BPF_OP(OP) | BPF_K, \
    .dst_reg = DST,                          \
    .src_reg = 0,                            \
    .off   = 0,                              \
    .imm   = IMM })

#define BPF_ALU32_IMM(OP, DST, IMM)        \
  ((struct bpf_insn) {                     \
    .code  = BPF_ALU | BPF_OP(OP) | BPF_K, \
    .dst_reg = DST,                        \
    .src_reg = 0,                          \
    .off   = 0,                            \
    .imm   = IMM })

/* Short form of mov, dst_reg = src_reg */

#define BPF_MOV64_REG(DST, SRC)           \
  ((struct bpf_insn) {                    \
    .code  = BPF_ALU64 | BPF_MOV | BPF_X, \
    .dst_reg = DST,                       \
    .src_reg = SRC,                       \
    .off   = 0,                           \
    .imm   = 0 })

#define BPF_MOV32_REG(DST, SRC)         \
  ((struct bpf_insn) {                  \
    .code  = BPF_ALU | BPF_MOV | BPF_X, \
    .dst_reg = DST,                     \
    .src_reg = SRC,                     \
    .off   = 0,                         \
    .imm   = 0 })

/* Short form of mov, dst_reg = imm32 */

#define BPF_MOV64_IMM(DST, IMM)           \
  ((struct bpf_insn) {                    \
    .code  = BPF_ALU64 | BPF_MOV | BPF_K, \
    .dst_reg = DST,                       \
    .src_reg = 0,                         \
    .off   = 0,                           \
    .imm   = IMM })

#define BPF_MOV32_IMM(DST, IMM)         \
  ((struct bpf_insn) {                  \
    .code  = BPF_ALU | BPF_MOV | BPF_K, \
    .dst_reg = DST,                     \
    .src_reg = 0,                       \
    .off   = 0,                         \
    .imm   = IMM })

/* BPF_LD_IMM64 macro encodes single 'load 64-bit immediate' insn */
#define BPF_LD_IMM64(DST, IMM)          \
  BPF_LD_IMM64_RAW(DST, 0, IMM)

#define BPF_LD_IMM64_RAW(DST, SRC, IMM)       \
  ((struct bpf_insn) {                        \
    .code  = BPF_LD | BPF_DW | BPF_IMM,       \
    .dst_reg = DST,                           \
    .src_reg = SRC,                           \
    .off   = 0,                               \
    .imm   = (__u32) (IMM) }),                \
  ((struct bpf_insn) {                        \
    .code  = 0, /* zero is reserved opcode */ \
    .dst_reg = 0,                             \
    .src_reg = 0,                             \
    .off   = 0,                               \
    .imm   = ((__u64) (IMM)) >> 32 })

#ifndef BPF_PSEUDO_MAP_FD
# define BPF_PSEUDO_MAP_FD  1
#endif

/* pseudo BPF_LD_IMM64 insn used to refer to process-local map_fd */
#define BPF_LD_MAP_FD(DST, MAP_FD)        \
  BPF_LD_IMM64_RAW(DST, BPF_PSEUDO_MAP_FD, MAP_FD)


/* Direct packet access, R0 = *(uint *) (skb->data + imm32) */

#define BPF_LD_ABS(SIZE, IMM)                   \
  ((struct bpf_insn) {                          \
    .code  = BPF_LD | BPF_SIZE(SIZE) | BPF_ABS, \
    .dst_reg = 0,                               \
    .src_reg = 0,                               \
    .off   = 0,                                 \
    .imm   = IMM })

/* Memory load, dst_reg = *(uint *) (src_reg + off16) */

#define BPF_LDX_MEM(SIZE, DST, SRC, OFF)         \
  ((struct bpf_insn) {                           \
    .code  = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM, \
    .dst_reg = DST,                              \
    .src_reg = SRC,                              \
    .off   = OFF,                                \
    .imm   = 0 })

/* Memory store, *(uint *) (dst_reg + off16) = src_reg */

#define BPF_STX_MEM(SIZE, DST, SRC, OFF)         \
  ((struct bpf_insn) {                           \
    .code  = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM, \
    .dst_reg = DST,                              \
    .src_reg = SRC,                              \
    .off   = OFF,                                \
    .imm   = 0 })

/* Atomic memory add, *(uint *)(dst_reg + off16) += src_reg */

#define BPF_STX_XADD(SIZE, DST, SRC, OFF)         \
  ((struct bpf_insn) {                            \
    .code  = BPF_STX | BPF_SIZE(SIZE) | BPF_XADD, \
    .dst_reg = DST,                               \
    .src_reg = SRC,                               \
    .off   = OFF,                                 \
    .imm   = 0 })

/* Memory store, *(uint *) (dst_reg + off16) = imm32 */

#define BPF_ST_MEM(SIZE, DST, OFF, IMM)         \
  ((struct bpf_insn) {                          \
    .code  = BPF_ST | BPF_SIZE(SIZE) | BPF_MEM, \
    .dst_reg = DST,                             \
    .src_reg = 0,                               \
    .off   = OFF,                               \
    .imm   = IMM })

/* Conditional jumps against registers, if (dst_reg 'op' src_reg) goto pc + off16 */

#define BPF_JMP_REG(OP, DST, SRC, OFF)     \
  ((struct bpf_insn) {                     \
    .code  = BPF_JMP | BPF_OP(OP) | BPF_X, \
    .dst_reg = DST,                        \
    .src_reg = SRC,                        \
    .off   = OFF,                          \
    .imm   = 0 })

/* Like BPF_JMP_REG, but with 32-bit wide operands for comparison. */

#define BPF_JMP32_REG(OP, DST, SRC, OFF)     \
  ((struct bpf_insn) {                       \
    .code  = BPF_JMP32 | BPF_OP(OP) | BPF_X, \
    .dst_reg = DST,                          \
    .src_reg = SRC,                          \
    .off   = OFF,                            \
    .imm   = 0 })

/* Conditional jumps against immediates, if (dst_reg 'op' imm32) goto pc + off16 */

#define BPF_JMP_IMM(OP, DST, IMM, OFF)     \
  ((struct bpf_insn) {                     \
    .code  = BPF_JMP | BPF_OP(OP) | BPF_K, \
    .dst_reg = DST,                        \
    .src_reg = 0,                          \
    .off   = OFF,                          \
    .imm   = IMM })

/* Like BPF_JMP_IMM, but with 32-bit wide operands for comparison. */

#define BPF_JMP32_IMM(OP, DST, IMM, OFF)     \
  ((struct bpf_insn) {                       \
    .code  = BPF_JMP32 | BPF_OP(OP) | BPF_K, \
    .dst_reg = DST,                          \
    .src_reg = 0,                            \
    .off   = OFF,                            \
    .imm   = IMM })

/* Raw code statement block */

#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM) \
  ((struct bpf_insn) {                         \
    .code  = CODE,                             \
    .dst_reg = DST,                            \
    .src_reg = SRC,                            \
    .off   = OFF,                              \
    .imm   = IMM })

/* Program exit */

#define BPF_EXIT_INSN()          \
  ((struct bpf_insn) {           \
    .code  = BPF_JMP | BPF_EXIT, \
    .dst_reg = 0,                \
    .src_reg = 0,                \
    .off   = 0,                  \
    .imm   = 0 })

/*
  From kernel source tree: include/linux/filter.h
  https://github.com/torvalds/linux/blob/master/include/linux/filter.h
*/

/* Endianess conversion, cpu_to_{l,b}e(), {l,b}e_to_cpu() */

#define BPF_ENDIAN(TYPE, DST, LEN)              \
  ((struct bpf_insn) {                          \
    .code  = BPF_ALU | BPF_END | BPF_SRC(TYPE), \
    .dst_reg = DST,                             \
    .src_reg = 0,                               \
    .off   = 0,                                 \
    .imm   = LEN })

/* Special form of mov32, used for doing explicit zero extension on dst. */
#define BPF_ZEXT_REG(DST)               \
  ((struct bpf_insn) {                  \
    .code  = BPF_ALU | BPF_MOV | BPF_X, \
    .dst_reg = DST,                     \
    .src_reg = DST,                     \
    .off   = 0,                         \
    .imm   = 1 })

static inline bool insn_is_zext(const struct bpf_insn *insn) {
  return insn->code == (BPF_ALU | BPF_MOV | BPF_X) && insn->imm == 1;
}

/* Indirect packet access, R0 = *(uint *) (skb->data + src_reg + imm32) */

#define BPF_LD_IND(SIZE, SRC, IMM)              \
  ((struct bpf_insn) {                          \
    .code  = BPF_LD | BPF_SIZE(SIZE) | BPF_IND, \
    .dst_reg = 0,                               \
    .src_reg = SRC,                             \
    .off   = 0,                                 \
    .imm   = IMM })

/*
 * Atomic operations:
 *
 *   BPF_ADD                  *(uint *) (dst_reg + off16) += src_reg
 *   BPF_AND                  *(uint *) (dst_reg + off16) &= src_reg
 *   BPF_OR                   *(uint *) (dst_reg + off16) |= src_reg
 *   BPF_XOR                  *(uint *) (dst_reg + off16) ^= src_reg
 *   BPF_ADD | BPF_FETCH      src_reg = atomic_fetch_add(dst_reg + off16, src_reg);
 *   BPF_AND | BPF_FETCH      src_reg = atomic_fetch_and(dst_reg + off16, src_reg);
 *   BPF_OR | BPF_FETCH       src_reg = atomic_fetch_or(dst_reg + off16, src_reg);
 *   BPF_XOR | BPF_FETCH      src_reg = atomic_fetch_xor(dst_reg + off16, src_reg);
 *   BPF_XCHG                 src_reg = atomic_xchg(dst_reg + off16, src_reg);
 *   BPF_CMPXCHG              r0 = atomic_cmpxchg(dst_reg + off16, r0, src_reg);
 */

#define BPF_ATOMIC_OP(SIZE, OP, DST, SRC, OFF)      \
  ((struct bpf_insn) {                              \
    .code  = BPF_STX | BPF_SIZE(SIZE) | BPF_ATOMIC, \
    .dst_reg = DST,                                 \
    .src_reg = SRC,                                 \
    .off   = OFF,                                   \
    .imm   = OP })

/* Unconditional jumps, goto pc + off16 */

#define BPF_JMP_A(OFF)         \
  ((struct bpf_insn) {         \
    .code  = BPF_JMP | BPF_JA, \
    .dst_reg = 0,              \
    .src_reg = 0,              \
    .off   = OFF,              \
    .imm   = 0 })

/* Relative call */

#define BPF_CALL_REL(TGT)        \
  ((struct bpf_insn) {           \
    .code  = BPF_JMP | BPF_CALL, \
    .dst_reg = 0,                \
    .src_reg = BPF_PSEUDO_CALL,  \
    .off   = 0,                  \
    .imm   = TGT })

/* Function call */

#define BPF_CAST_CALL(x) \
    ((u64 (*)(u64, u64, u64, u64, u64))(x))

u64 __bpf_call_base(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5);
#define __bpf_call_base_args                                   \
  ((u64 (*)(u64, u64, u64, u64, u64, const struct bpf_insn *)) \
   (void *)__bpf_call_base)

#define BPF_EMIT_CALL(FUNC)                \
  ((struct bpf_insn) {                     \
    .code  = BPF_JMP | BPF_CALL,           \
    .dst_reg = 0,                          \
    .src_reg = 0,                          \
    .off   = 0,                            \
    .imm   = ((FUNC) - __bpf_call_base) })

#endif

#ifdef __cplusplus
}
#endif
