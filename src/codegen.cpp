#include <../headers/bpf_insn.h>
#include "codegen.hpp"

static inline Nat max_insns() {
  Nat max_insns = 0;
  for (Nat i = 0; i < ASIZE; ++i) {
    if (type(i) == Instruction)
      ++max_insns;
    if (isa(i) == ld64 || isa(i) == ldmapfd)
      ++max_insns;
  }
  return max_insns;
}

static inline __u8 reg_(Nat i, Nat j) {
  Regs r = reg(i, j).reg;
  MATCH (r) {
    case r0:  return BPF_REG_0;  END
    case r1:  return BPF_REG_1;  END
    case r2:  return BPF_REG_2;  END
    case r3:  return BPF_REG_3;  END
    case r4:  return BPF_REG_4;  END
    case r5:  return BPF_REG_5;  END
    case r6:  return BPF_REG_6;  END
    case r7:  return BPF_REG_7;  END
    case r8:  return BPF_REG_8;  END
    case r9:  return BPF_REG_9;  END
    case r10: return BPF_REG_10; END
    _
      pp_ast();
      error(ERR_STR "reg_(): unknown register: ", pp_reg(r),
            "\nat: [", i, ", ", j,"]", "\ncategorical variable: ", r);
      return 1;
    END
  }
}

static inline Str reg_str(Nat i, Nat j) {
  Regs r = reg(i, j).reg;
  MATCH (r) {
    case r0:  return "BPF_REG_0";  END
    case r1:  return "BPF_REG_1";  END
    case r2:  return "BPF_REG_2";  END
    case r3:  return "BPF_REG_3";  END
    case r4:  return "BPF_REG_4";  END
    case r5:  return "BPF_REG_5";  END
    case r6:  return "BPF_REG_6";  END
    case r7:  return "BPF_REG_7";  END
    case r8:  return "BPF_REG_8";  END
    case r9:  return "BPF_REG_9";  END
    case r10: return "BPF_REG_10"; END
    _
      pp_ast();
      error(ERR_STR "reg_str(): unknown register: ", pp_reg(r),
            "\nat: [", i, ", ", j,"]", "\ncategorical variable: ", r);
      return "";
    END
  }
}

static inline Int32 val(Nat i, Nat j) {
  return imm(i, j).val;
}

void codegen(Str out_fname) {
  bpf_insn prog[MAX_INSNS];
  Type     ty2;
  Nat      insns = 0;

  for (Nat i=0; i<ASIZE; ++i) {
    if (type(i) != Instruction)
      continue;

    ty2 = optype(SND, i);

    MATCH (isa(i)) {
    /* ALU instructions: */
    /* 64-bit: */
    /* add dst src|imm */
    case add:
      if (ty2 == Immediate)
        prog[insns++] = BPF_ALU64_IMM(BPF_ADD, reg_(FST, i), val(SND, i));
      else
        prog[insns++] = BPF_ALU64_REG(BPF_ADD, reg_(FST, i), reg_(SND, i));
    END

    /* sub dst src|imm */
    case sub:
      if (ty2 == Immediate)
        prog[insns++] = BPF_ALU64_IMM(BPF_SUB, reg_(FST, i), val(SND, i));
      else
        prog[insns++] = BPF_ALU64_REG(BPF_SUB, reg_(FST, i), reg_(SND, i));
    END

    /* mul dst src|imm */
    case mul:
      if (ty2 == Immediate)
        prog[insns++] = BPF_ALU64_IMM(BPF_MUL, reg_(FST, i), val(SND, i));
      else
        prog[insns++] = BPF_ALU64_REG(BPF_MUL, reg_(FST, i), reg_(SND, i));
    END

    /* div dst src|imm */
    case div_:
      if (ty2 == Immediate)
        prog[insns++] = BPF_ALU64_IMM(BPF_DIV, reg_(FST, i), val(SND, i));
      else
        prog[insns++] = BPF_ALU64_REG(BPF_DIV, reg_(FST, i), reg_(SND, i));
    END

    /* or dst src|imm */
    case or_:
      if (ty2 == Immediate)
        prog[insns++] = BPF_ALU64_IMM(BPF_OR, reg_(FST, i), val(SND, i));
      else
        prog[insns++] = BPF_ALU64_REG(BPF_OR, reg_(FST, i), reg_(SND, i));
    END

    /* and dst src|imm */
    case and_:
      if (ty2 == Immediate)
        prog[insns++] = BPF_ALU64_IMM(BPF_AND, reg_(FST, i), val(SND, i));
      else
        prog[insns++] = BPF_ALU64_REG(BPF_AND, reg_(FST, i), reg_(SND, i));
    END

    /* lsh dst src|imm */
    case lsh:
      if (ty2 == Immediate)
        prog[insns++] = BPF_ALU64_IMM(BPF_LSH, reg_(FST, i), val(SND, i));
      else
        prog[insns++] = BPF_ALU64_REG(BPF_LSH, reg_(FST, i), reg_(SND, i));
    END

    /* rsh dst src|imm */
    case rsh:
      if (ty2 == Immediate)
        prog[insns++] = BPF_ALU64_IMM(BPF_RSH, reg_(FST, i), val(SND, i));
      else
        prog[insns++] = BPF_ALU64_REG(BPF_RSH, reg_(FST, i), reg_(SND, i));
    END

    /* neg dst */
    case neg:
        prog[insns++] = BPF_ALU64_IMM(BPF_NEG, reg_(FST, i), 0);
    END

    /* mod dst src|imm */
    case mod:
      if (ty2 == Immediate)
        prog[insns++] = BPF_ALU64_IMM(BPF_MOD, reg_(FST, i), val(SND, i));
      else
        prog[insns++] = BPF_ALU64_REG(BPF_MOD, reg_(FST, i), reg_(SND, i));
    END

    /* xor dst src|imm */
    case xor_:
      if (ty2 == Immediate)
        prog[insns++] = BPF_ALU64_IMM(BPF_XOR, reg_(FST, i), val(SND, i));
      else
        prog[insns++] = BPF_ALU64_REG(BPF_XOR, reg_(FST, i), reg_(SND, i));
    END

    /* mov dst src|imm */
    case mov:
      if (ty2 == Immediate)
        prog[insns++] = BPF_ALU64_IMM(BPF_MOV, reg_(FST, i), val(SND, i));
      else
        prog[insns++] = BPF_ALU64_REG(BPF_MOV, reg_(FST, i), reg_(SND, i));
    END

    /* arsh dst src|imm */
    case arsh:
      if (ty2 == Immediate)
        prog[insns++] = BPF_ALU64_IMM(BPF_ARSH, reg_(FST, i), val(SND, i));
      else
        prog[insns++] = BPF_ALU64_REG(BPF_ARSH, reg_(FST, i), reg_(SND, i));
    END

    /* 32-bit: */
    /* add32 dst src|imm */
    case add32:
      if (ty2 == Immediate)
        prog[insns++] = BPF_ALU32_IMM(BPF_ADD, reg_(FST, i), val(SND, i));
      else
        prog[insns++] = BPF_ALU32_REG(BPF_ADD, reg_(FST, i), reg_(SND, i));
    END

    /* sub32 dst src|imm */
    case sub32:
      if (ty2 == Immediate)
        prog[insns++] = BPF_ALU32_IMM(BPF_SUB, reg_(FST, i), val(SND, i));
      else
        prog[insns++] = BPF_ALU32_REG(BPF_SUB, reg_(FST, i), reg_(SND, i));
    END

    /* mul32 dst src|imm */
    case mul32:
      if (ty2 == Immediate)
        prog[insns++] = BPF_ALU32_IMM(BPF_MUL, reg_(FST, i), val(SND, i));
      else
        prog[insns++] = BPF_ALU32_REG(BPF_MUL, reg_(FST, i), reg_(SND, i));
    END

    /* div32 dst src|imm */
    case div32:
      if (ty2 == Immediate)
        prog[insns++] = BPF_ALU32_IMM(BPF_DIV, reg_(FST, i), val(SND, i));
      else
        prog[insns++] = BPF_ALU32_REG(BPF_DIV, reg_(FST, i), reg_(SND, i));
    END

    /* or32 dst src|imm */
    case or32:
      if (ty2 == Immediate)
        prog[insns++] = BPF_ALU32_IMM(BPF_OR, reg_(FST, i), val(SND, i));
      else
        prog[insns++] = BPF_ALU32_REG(BPF_OR, reg_(FST, i), reg_(SND, i));
    END

    /* and32 dst src|imm */
    case and32:
      if (ty2 == Immediate)
        prog[insns++] = BPF_ALU32_IMM(BPF_AND, reg_(FST, i), val(SND, i));
      else
        prog[insns++] = BPF_ALU32_REG(BPF_AND, reg_(FST, i), reg_(SND, i));
    END

    /* lsh32 dst src|imm */
    case lsh32:
      if (ty2 == Immediate)
        prog[insns++] = BPF_ALU32_IMM(BPF_LSH, reg_(FST, i), val(SND, i));
      else
        prog[insns++] = BPF_ALU32_REG(BPF_LSH, reg_(FST, i), reg_(SND, i));
    END

    /* rsh32 dst src|imm */
    case rsh32:
      if (ty2 == Immediate)
        prog[insns++] = BPF_ALU32_IMM(BPF_RSH, reg_(FST, i), val(SND, i));
      else
        prog[insns++] = BPF_ALU32_REG(BPF_RSH, reg_(FST, i), reg_(SND, i));
    END

    /* neg32 dst */
    case neg32:
        prog[insns++] = BPF_ALU32_IMM(BPF_NEG, reg_(FST, i), 0);
    END

    /* mod32 dst src|imm */
    case mod32:
      if (ty2 == Immediate)
        prog[insns++] = BPF_ALU32_IMM(BPF_MOD, reg_(FST, i), val(SND, i));
      else
        prog[insns++] = BPF_ALU32_REG(BPF_MOD, reg_(FST, i), reg_(SND, i));
    END

    /* xor32 dst src|imm */
    case xor32:
      if (ty2 == Immediate)
        prog[insns++] = BPF_ALU32_IMM(BPF_XOR, reg_(FST, i), val(SND, i));
      else
        prog[insns++] = BPF_ALU32_REG(BPF_XOR, reg_(FST, i), reg_(SND, i));
    END

    /* mov32 dst src|imm */
    case mov32:
      if (ty2 == Immediate)
        prog[insns++] = BPF_ALU32_IMM(BPF_MOV, reg_(FST, i), val(SND, i));
      else
        prog[insns++] = BPF_ALU32_REG(BPF_MOV, reg_(FST, i), reg_(SND, i));
    END

    /* arsh32 dst src|imm */
    case arsh32:
      if (ty2 == Immediate)
        prog[insns++] = BPF_ALU32_IMM(BPF_ARSH, reg_(FST, i), val(SND, i));
      else
        prog[insns++] = BPF_ALU32_REG(BPF_ARSH, reg_(FST, i), reg_(SND, i));
    END

    /* mov32 dst src|imm */
    /*
    case mov32:
      if (ty2 == Immediate)
        prog[insns++] = BPF_MOV32_IMM(reg_(FST, i),
                                         val(SND, i));
      else
        prog[insns++] = BPF_MOV32_REG(reg_(FST, i),
                                         reg_(SND, i));
    END
    */

    /* Endianess conversion (Byteswap) instructions: */
    /* le16 dst */
    case le16:
      prog[insns++] = BPF_ENDIAN(BPF_TO_LE, reg_(FST, i), 16);
    END

    /* le32 dst */
    case le32:
      prog[insns++] = BPF_ENDIAN(BPF_TO_LE, reg_(FST, i), 32);
    END

    /* le64 dst */
    case le64:
      prog[insns++] = BPF_ENDIAN(BPF_TO_LE, reg_(FST, i), 64);
    END

    /* be16 dst */
    case be16:
      prog[insns++] = BPF_ENDIAN(BPF_TO_BE, reg_(FST, i), 16);
    END

    /* be32 dst */
    case be32:
      prog[insns++] = BPF_ENDIAN(BPF_TO_BE, reg_(FST, i), 32);
    END

    /* be64 dst */
    case be64:
      prog[insns++] = BPF_ENDIAN(BPF_TO_BE, reg_(FST, i), 64);
    END

    /* Atomic operations: */
    /* addx16 dst src off */
    case addx16:
      prog[insns++] =
        BPF_ATOMIC_OP(16, BPF_ADD, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* addx32 dst src off */
    case addx32:
      prog[insns++] =
        BPF_ATOMIC_OP(32, BPF_ADD, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* addx64 dst src off */
    case addx64:
      prog[insns++] =
        BPF_ATOMIC_OP(64, BPF_ADD, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* andx16 dst src off */
    case andx16:
      prog[insns++] =
        BPF_ATOMIC_OP(16, BPF_AND, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* andx32 dst src off */
    case andx32:
      prog[insns++] =
        BPF_ATOMIC_OP(32, BPF_AND, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* andx64 dst src off */
    case andx64:
      prog[insns++] =
        BPF_ATOMIC_OP(64, BPF_AND, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* orx16 dst src off */
    case orx16:
      prog[insns++] =
        BPF_ATOMIC_OP(16, BPF_OR, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* orx32 dst src off */
    case orx32:
      prog[insns++] =
        BPF_ATOMIC_OP(32, BPF_OR, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* orx64 dst src off */
    case orx64:
      prog[insns++] =
        BPF_ATOMIC_OP(64, BPF_OR, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* xorx16 dst src off */
    case xorx16:
      prog[insns++] =
        BPF_ATOMIC_OP(16, BPF_XOR, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* xorx32 dst src off */
    case xorx32:
      prog[insns++] =
        BPF_ATOMIC_OP(32, BPF_XOR, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* xorx64 dst src off */
    case xorx64:
      prog[insns++] =
        BPF_ATOMIC_OP(64, BPF_XOR, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* addfx16 dst src off */
    case addfx16:
      prog[insns++] =
        BPF_ATOMIC_OP(16, BPF_ADD | BPF_FETCH, reg_(FST, i), reg_(SND, i),
                                               (__s16)val(TRD, i));
    END

    /* addfx32 dst src off */
    case addfx32:
      prog[insns++] =
        BPF_ATOMIC_OP(32, BPF_ADD | BPF_FETCH, reg_(FST, i), reg_(SND, i),
                                               (__s16)val(TRD, i));
    END

    /* addfx64 dst src off */
    case addfx64:
      prog[insns++] =
        BPF_ATOMIC_OP(64, BPF_ADD | BPF_FETCH, reg_(FST, i), reg_(SND, i),
                                               (__s16)val(TRD, i));
    END

    /* andfx16 dst src off */
    case andfx16:
      prog[insns++] =
        BPF_ATOMIC_OP(16, BPF_AND | BPF_FETCH, reg_(FST, i), reg_(SND, i),
                                               (__s16)val(TRD, i));
    END

    /* andfx32 dst src off */
    case andfx32:
      prog[insns++] =
        BPF_ATOMIC_OP(32, BPF_AND | BPF_FETCH, reg_(FST, i), reg_(SND, i),
                                               (__s16)val(TRD, i));
    END

    /* andfx64 dst src off */
    case andfx64:
      prog[insns++] =
        BPF_ATOMIC_OP(64, BPF_AND | BPF_FETCH, reg_(FST, i), reg_(SND, i),
                                               (__s16)val(TRD, i));
    END

    /* orfx16 dst src off */
    case orfx16:
      prog[insns++] =
        BPF_ATOMIC_OP(16, BPF_OR | BPF_FETCH, reg_(FST, i), reg_(SND, i),
                                              (__s16)val(TRD, i));
    END

    /* orfx32 dst src off */
    case orfx32:
      prog[insns++] =
        BPF_ATOMIC_OP(32, BPF_OR | BPF_FETCH, reg_(FST, i), reg_(SND, i),
                                              (__s16)val(TRD, i));
    END

    /* orfx64 dst src off */
    case orfx64:
      prog[insns++] =
        BPF_ATOMIC_OP(64, BPF_OR | BPF_FETCH, reg_(FST, i), reg_(SND, i),
                                              (__s16)val(TRD, i));
    END

    /* xorfx16 dst src off */
    case xorfx16:
      prog[insns++] =
        BPF_ATOMIC_OP(16, BPF_XOR | BPF_FETCH, reg_(FST, i), reg_(SND, i),
                                               (__s16)val(TRD, i));
    END

    /* xorfx32 dst src off */
    case xorfx32:
      prog[insns++] =
        BPF_ATOMIC_OP(32, BPF_XOR | BPF_FETCH, reg_(FST, i), reg_(SND, i),
                                               (__s16)val(TRD, i));
    END

    /* xorfx64 dst src off */
    case xorfx64:
      prog[insns++] =
        BPF_ATOMIC_OP(64, BPF_XOR | BPF_FETCH, reg_(FST, i), reg_(SND, i),
                                               (__s16)val(TRD, i));
    END

    /* xchgx16 dst src off */
    case xchgx16:
      prog[insns++] =
        BPF_ATOMIC_OP(16, BPF_XCHG, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* xchgx32 dst src off */
    case xchgx32:
      prog[insns++] =
        BPF_ATOMIC_OP(32, BPF_XCHG, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* xchgx64 dst src off */
    case xchgx64:
      prog[insns++] = BPF_ATOMIC_OP(64, BPF_XCHG, reg_(FST, i), reg_(SND, i),
                                                  (__s16)val(TRD, i));
    END

    /* cmpxchgx16 dst src off */
    case cmpxchgx16:
      prog[insns++] = BPF_ATOMIC_OP(16, BPF_CMPXCHG, reg_(FST, i), reg_(SND, i),
                                                     (__s16)val(TRD, i));
    END

    /* cmpxchgx32 dst src off */
    case cmpxchgx32:
      prog[insns++] = BPF_ATOMIC_OP(32, BPF_CMPXCHG, reg_(FST, i), reg_(SND, i),
                                                     (__s16)val(TRD, i));
    END

    /* cmpxchgx64 dst src off */
    case cmpxchgx64:
      prog[insns++] = BPF_ATOMIC_OP(64, BPF_CMPXCHG, reg_(FST, i), reg_(SND, i),
                                                     (__s16)val(TRD, i));
    END

    /* ldmapfd dst imm */
    case ldmapfd:
      prog[insns++] =
        BPF_LD_IMM64_RAW_1(reg_(FST, i), BPF_PSEUDO_MAP_FD, val(SND, i));
      prog[insns++] =
        BPF_LD_IMM64_RAW_2(reg_(FST, i), BPF_PSEUDO_MAP_FD, val(SND, i));
    END

    /* ld64 dst imm */
    case ld64:
      prog[insns++] = BPF_LD_IMM64_RAW_1(reg_(FST, i), 0, val(SND, i));
      prog[insns++] = BPF_LD_IMM64_RAW_2(reg_(FST, i), 0, val(SND, i));
    END

    /* ldabs8 imm */
    case ldabs8:
      prog[insns++] = BPF_LD_ABS(8, val(FST, i));
    END

    /* ldabs16 imm */
    case ldabs16:
      prog[insns++] = BPF_LD_ABS(16, val(FST, i));
    END

    /* ldabs32 imm */
    case ldabs32:
      prog[insns++] = BPF_LD_ABS(32, val(FST, i));
    END

    /* ldabs64 imm */
    case ldabs64:
      prog[insns++] = BPF_LD_ABS(64, val(FST, i));
    END

    /* ldind8 src imm */
    case ldind8:
      prog[insns++] =
        BPF_LD_IND(8, reg_(FST, i), val(SND, i));
    END

    /* ldind16 src imm */
    case ldind16:
      prog[insns++] =
        BPF_LD_IND(16, reg_(FST, i), val(SND, i));
    END

    /* ldind32 src imm */
    case ldind32:
      prog[insns++] =
        BPF_LD_IND(32, reg_(FST, i), val(SND, i));
    END

    /* ldind64 src imm */
    case ldind64:
      prog[insns++] =
        BPF_LD_IND(64, reg_(FST, i), val(SND, i));
    END

    /* ldx8 dst src off */
    case ldx8:
      prog[insns++] =
        BPF_LDX_MEM(8, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* ldx16 dst src off */
    case ldx16:
      prog[insns++] =
        BPF_LDX_MEM(16, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* ldx32 dst src off */
    case ldx32:
      prog[insns++] =
        BPF_LDX_MEM(32, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* ldx64 dst src off */
    case ldx64:
      prog[insns++] =
        BPF_LDX_MEM(64, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* st8 dst off imm */
    case st8:
      prog[insns++] =
        BPF_ST_MEM(8, reg_(FST, i), (__s16)val(SND, i), val(TRD, i));
    END

    /* st16 dst off imm */
    case st16:
      prog[insns++] =
        BPF_ST_MEM(16, reg_(FST, i), (__s16)val(SND, i), val(TRD, i));
    END

    /* st32 dst off imm */
    case st32:
      prog[insns++] =
        BPF_ST_MEM(32, reg_(FST, i), (__s16)val(SND, i), val(TRD, i));
    END

    /* st64 dst off imm */
    case st64:
      prog[insns++] =
        BPF_ST_MEM(64, reg_(FST, i), (__s16)val(SND, i), val(TRD, i));
    END

    /* stx8 dst src off */
    case stx8:
      prog[insns++] =
        BPF_STX_MEM(8, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* stx16 dst src off */
    case stx16:
      prog[insns++] =
        BPF_STX_MEM(16, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* stx32 dst src off */
    case stx32:
      prog[insns++] =
        BPF_STX_MEM(32, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* stx64 dst src off */
    case stx64:
      prog[insns++] =
        BPF_STX_MEM(64, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* stxx8 dst src off */
    case stxx8:
      prog[insns++] =
        BPF_STX_XADD(8, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* stxx16 dst src off */
    case stxx16:
      prog[insns++] =
        BPF_STX_XADD(16, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* stxx32 dst src off */
    case stxx32:
      prog[insns++] =
        BPF_STX_XADD(32, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* stxx64 dst src off */
    case stxx64:
      prog[insns++] =
        BPF_STX_XADD(64, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* Branch instructions: */
    /* 64-bit: */

    /* ja off */
    case ja:
      prog[insns++] = BPF_JMP_A((__s16)val(FST, i));
    END

    /* jeq dst src|imm off */
    case jeq:
      if (ty2 == Immediate)
        prog[insns++] =
           BPF_JMP_IMM(BPF_JEQ, reg_(FST, i), val(SND, i), (__s16)val(TRD, i));
      else
        prog[insns++] =
          BPF_JMP_REG(BPF_JEQ, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* jgt dst src|imm off */
    case jgt:
      if (ty2 == Immediate)
        prog[insns++] =
           BPF_JMP_IMM(BPF_JGT, reg_(FST, i), val(SND, i), (__s16)val(TRD, i));
      else
        prog[insns++] =
          BPF_JMP_REG(BPF_JGT, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* jge dst src|imm off */
    case jge:
      if (ty2 == Immediate)
        prog[insns++] =
           BPF_JMP_IMM(BPF_JGE, reg_(FST, i), val(SND, i), (__s16)val(TRD, i));
      else
        prog[insns++] =
          BPF_JMP_REG(BPF_JGE, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* jlt dst src|imm off */
    case jlt:
      if (ty2 == Immediate)
        prog[insns++] =
           BPF_JMP_IMM(BPF_JLT, reg_(FST, i), val(SND, i), (__s16)val(TRD, i));
      else
        prog[insns++] =
          BPF_JMP_REG(BPF_JLT, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* jle dst src|imm off */
    case jle:
      if (ty2 == Immediate)
        prog[insns++] =
           BPF_JMP_IMM(BPF_JLE, reg_(FST, i), val(SND, i), (__s16)val(TRD, i));
      else
        prog[insns++] =
          BPF_JMP_REG(BPF_JLE, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* jset dst src|imm off */
    case jset:
      if (ty2 == Immediate)
        prog[insns++] =
           BPF_JMP_IMM(BPF_JSET, reg_(FST, i), val(SND, i), (__s16)val(TRD, i));
      else
        prog[insns++] =
          BPF_JMP_REG(BPF_JSET, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* jne dst src|imm off */
    case jne:
      if (ty2 == Immediate)
        prog[insns++] =
           BPF_JMP_IMM(BPF_JNE, reg_(FST, i), val(SND, i), (__s16)val(TRD, i));
      else
        prog[insns++] =
          BPF_JMP_REG(BPF_JNE, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* jsgt dst src|imm off */
    case jsgt:
      if (ty2 == Immediate)
        prog[insns++] =
           BPF_JMP_IMM(BPF_JSGT, reg_(FST, i), val(SND, i), (__s16)val(TRD, i));
      else
        prog[insns++] =
          BPF_JMP_REG(BPF_JSGT, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* jsge dst src|imm off */
    case jsge:
      if (ty2 == Immediate)
        prog[insns++] =
           BPF_JMP_IMM(BPF_JSGE, reg_(FST, i), val(SND, i), (__s16)val(TRD, i));
      else
        prog[insns++] =
          BPF_JMP_REG(BPF_JSGE, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* jslt dst src|imm off */
    case jslt:
      if (ty2 == Immediate)
        prog[insns++] =
           BPF_JMP_IMM(BPF_JSLT, reg_(FST, i), val(SND, i), (__s16)val(TRD, i));
      else
        prog[insns++] =
          BPF_JMP_REG(BPF_JSLT, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* jsle dst src|imm off */
    case jsle:
      if (ty2 == Immediate)
        prog[insns++] =
           BPF_JMP_IMM(BPF_JSLE, reg_(FST, i), val(SND, i), (__s16)val(TRD, i));
      else
        prog[insns++] =
          BPF_JMP_REG(BPF_JSLE, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* call imm */
    case call:
      error(ERR_STR "the `call` instruction is not yet supported.");
    END

    /* rel imm */
    case rel:
      prog[insns++] = BPF_CALL_REL(val(FST, i));
    END

    /* exit */
    case exit_:
      prog[insns++] = BPF_EXIT_INSN();
    END

    /* 32-bit: */

    /* jeq32 dst src|imm off */
    case jeq32:
      if (ty2 == Immediate)
        prog[insns++] =
           BPF_JMP32_IMM(BPF_JEQ, reg_(FST, i), val(SND, i), (__s16)val(TRD, i));
      else
        prog[insns++] =
          BPF_JMP32_REG(BPF_JEQ, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* jgt32 dst src|imm off */
    case jgt32:
      if (ty2 == Immediate)
        prog[insns++] =
           BPF_JMP32_IMM(BPF_JGT, reg_(FST, i), val(SND, i), (__s16)val(TRD, i));
      else
        prog[insns++] =
          BPF_JMP32_REG(BPF_JGT, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* jge32 dst src|imm off */
    case jge32:
      if (ty2 == Immediate)
        prog[insns++] =
           BPF_JMP32_IMM(BPF_JGE, reg_(FST, i), val(SND, i), (__s16)val(TRD, i));
      else
        prog[insns++] =
          BPF_JMP32_REG(BPF_JGE, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* jlt32 dst src|imm off */
    case jlt32:
      if (ty2 == Immediate)
        prog[insns++] =
           BPF_JMP32_IMM(BPF_JLT, reg_(FST, i),  val(SND, i), (__s16)val(TRD, i));
      else
        prog[insns++] =
          BPF_JMP32_REG(BPF_JLT, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* jle32 dst src|imm off */
    case jle32:
      if (ty2 == Immediate)
        prog[insns++] =
          BPF_JMP32_IMM(BPF_JLE, reg_(FST, i), val(SND, i), (__s16)val(TRD, i));
      else
        prog[insns++] =
          BPF_JMP32_REG(BPF_JLE, reg_(FST, i), reg_(SND, i), (__s16)val(TRD, i));
    END

    /* jset32 dst src|imm off */
    case jset32:
      if (ty2 == Immediate)
        prog[insns++] = BPF_JMP32_IMM(BPF_JSET,  reg_(FST, i), val(SND, i),
                                                 (__s16)val(TRD, i));
      else
        prog[insns++] = BPF_JMP32_REG(BPF_JSET, reg_(FST, i), reg_(SND, i),
                                                (__s16)val(TRD, i));
    END

    /* jne32 dst src|imm off */
    case jne32:
      if (ty2 == Immediate)
        prog[insns++] = BPF_JMP32_IMM(BPF_JNE, reg_(FST, i), val(SND, i),
                                               (__s16)val(TRD, i));
      else
        prog[insns++] = BPF_JMP32_REG(BPF_JNE, reg_(FST, i), reg_(SND, i),
                                               (__s16)val(TRD, i));
    END

    /* jsgt32 dst src|imm off */
    case jsgt32:
      if (ty2 == Immediate)
        prog[insns++] = BPF_JMP32_IMM(BPF_JSGT, reg_(FST, i), val(SND, i),
                                                (__s16)val(TRD, i));
      else
        prog[insns++] = BPF_JMP32_REG(BPF_JSGT, reg_(FST, i), reg_(SND, i),
                                                (__s16)val(TRD, i));
    END

    /* jsge32 dst src|imm off */
    case jsge32:
      if (ty2 == Immediate)
        prog[insns++] = BPF_JMP32_IMM(BPF_JSGE, reg_(FST, i), val(SND, i),
                                                (__s16)val(TRD, i));
      else
        prog[insns++] = BPF_JMP32_REG(BPF_JSGE, reg_(FST, i), reg_(SND, i),
                                                (__s16)val(TRD, i));
    END

    /* jslt32 dst src|imm off */
    case jslt32:
      if (ty2 == Immediate)
        prog[insns++] = BPF_JMP32_IMM(BPF_JSLT, reg_(FST, i), val(SND, i),
                                                (__s16)val(TRD, i));
      else
        prog[insns++] = BPF_JMP32_REG(BPF_JSLT, reg_(FST, i), reg_(SND, i),
                                                (__s16)val(TRD, i));
    END

    /* jsle32 dst src|imm off */
    case jsle32:
      if (ty2 == Immediate)
        prog[insns++] = BPF_JMP32_IMM(BPF_JSLE, reg_(FST, i), val(SND, i),
                                                (__s16)val(TRD, i));
      else
        prog[insns++] = BPF_JMP32_REG(BPF_JSLE, reg_(FST, i), reg_(SND, i),
                                                (__s16)val(TRD, i));
    END

    /* zext dst */
    case zext:
      prog[insns++] = BPF_ZEXT_REG(reg_(FST, i));
    END

    _
      error(ERR_STR "code generation: uncovered instruction: `",
            pp_ins(isa(i)), "` categorical variable: ", isa(i));
    END
    }
  }

  Int fd = open(out_fname.c_str(),
                O_CREAT | O_WRONLY | O_TRUNC, S_IREAD | S_IWUSR);
  if (fd == -1)
    error(ERR_STR "open() failed on `", out_fname, "`: ", strerror(errno));
  if(write(fd, prog, insns * sizeof(struct bpf_insn)) == -1)
    error(ERR_STR "write() failed on `", out_fname, "`: ", strerror(errno));
  close(fd);
}

void codegen_str(Str out_fname, Str struct_name) {
  Type ty2;
  Str  c_code;

  if (struct_name.size())
    c_code = "static struct bpf_insn " + struct_name + "["
           +  STR(max_insns()) + "] = {\n";
  else
    c_code = "static struct bpf_insn prog[" + STR(max_insns()) + "] = {\n";

  for (Nat i=0; i<ASIZE; ++i) {
    if (type(i) != Instruction)
      continue;

    ty2 = optype(SND, i);

    MATCH (isa(i)) {
    /* ALU instructions: */
    /* 64-bit: */
    /* add dst src|imm */
    case add:
      if (ty2 == Immediate)
        c_code += "BPF_ALU64_IMM(BPF_ADD, " + reg_str(FST, i)  + ", "
                                            + STR(val(SND, i)) + "),\n";
      else
        c_code += "BPF_ALU64_REG(BPF_ADD, " + reg_str(FST, i) + ", "
                                            + reg_str(SND, i) + "),\n";
    END

    /* sub dst src|imm */
    case sub:
      if (ty2 == Immediate)
        c_code += "BPF_ALU64_IMM(BPF_SUB, " + reg_str(FST, i)  + ", "
                                            + STR(val(SND, i)) + "),\n";
      else
        c_code += "BPF_ALU64_REG(BPF_SUB, " + reg_str(FST, i) + ", "
                                            + reg_str(SND, i) + "),\n";
    END

    /* mul dst src|imm */
    case mul:
      if (ty2 == Immediate)
        c_code += "BPF_ALU64_IMM(BPF_MUL, " + reg_str(FST, i)  + ", "
                                            + STR(val(SND, i)) + "),\n";
      else
        c_code += "BPF_ALU64_REG(BPF_MUL, " + reg_str(FST, i) + ", "
                                            + reg_str(SND, i) + "),\n";
    END

    /* div dst src|imm */
    case div_:
      if (ty2 == Immediate)
        c_code += "BPF_ALU64_IMM(BPF_DIV, " + reg_str(FST, i)  + ", "
                                            + STR(val(SND, i)) + "),\n";
      else
        c_code += "BPF_ALU64_REG(BPF_DIV, " + reg_str(FST, i) + ", "
                                            + reg_str(SND, i) + "),\n";
    END

    /* or dst src|imm */
    case or_:
      if (ty2 == Immediate)
        c_code += "BPF_ALU64_IMM(BPF_OR, "  + reg_str(FST, i)  + ", "
                                            + STR(val(SND, i)) + "),\n";
      else
        c_code += "BPF_ALU64_REG(BPF_OR, "  + reg_str(FST, i) + ", "
                                            + reg_str(SND, i) + "),\n";
    END

    /* and dst src|imm */
    case and_:
      if (ty2 == Immediate)
        c_code += "BPF_ALU64_IMM(BPF_AND, " + reg_str(FST, i)  + ", "
                                            + STR(val(SND, i)) + "),\n";
      else
        c_code += "BPF_ALU64_REG(BPF_AND, " + reg_str(FST, i) + ", "
                                            + reg_str(SND, i) + "),\n";
    END

    /* lsh dst src|imm */
    case lsh:
      if (ty2 == Immediate)
        c_code += "BPF_ALU64_IMM(BPF_LSH, " + reg_str(FST, i)  + ", "
                                            + STR(val(SND, i)) + "),\n";
      else
        c_code += "BPF_ALU64_REG(BPF_LSH, " + reg_str(FST, i) + ", "
                                            + reg_str(SND, i) + "),\n";
    END

    /* rsh dst src|imm */
    case rsh:
      if (ty2 == Immediate)
        c_code += "BPF_ALU64_IMM(BPF_RSH, " + reg_str(FST, i)  + ", "
                                            + STR(val(SND, i)) + "),\n";
      else
        c_code += "BPF_ALU64_REG(BPF_RSH, " + reg_str(FST, i) + ", "
                                            + reg_str(SND, i) + "),\n";
    END

    /* neg dst */
    case neg:
       c_code += "BPF_ALU64_IMM(BPF_NEG, " + reg_str(FST, i) + ", 0),\n";
    END

    /* mod dst src|imm */
    case mod:
      if (ty2 == Immediate)
        c_code += "BPF_ALU64_IMM(BPF_MOD, " + reg_str(FST, i)  + ", "
                                            + STR(val(SND, i)) + "),\n";
      else
        c_code += "BPF_ALU64_REG(BPF_MOD, " + reg_str(FST, i) + ", "
                                            + reg_str(SND, i) + "),\n";
    END

    /* xor dst src|imm */
    case xor_:
      if (ty2 == Immediate)
        c_code += "BPF_ALU64_IMM(BPF_XOR, " + reg_str(FST, i)  + ", "
                                            + STR(val(SND, i)) + "),\n";
      else
        c_code += "BPF_ALU64_REG(BPF_XOR, " + reg_str(FST, i) + ", "
                                            + reg_str(SND, i) + "),\n";
    END

    /* mov dst src|imm */
    case mov:
      if (ty2 == Immediate)
        c_code += "BPF_ALU64_IMM(BPF_MOV, " + reg_str(FST, i)  + ", "
                                            + STR(val(SND, i)) + "),\n";
      else
        c_code += "BPF_ALU64_REG(BPF_MOV, " + reg_str(FST, i) + ", "
                                            + reg_str(SND, i) + "),\n";
     END

    /* arsh dst src|imm */
    case arsh:
      if (ty2 == Immediate)
        c_code += "BPF_ALU64_IMM(BPF_ARSH, " + reg_str(FST, i)  + ", "
                                             + STR(val(SND, i)) + "),\n";
      else
        c_code += "BPF_ALU64_REG(BPF_ARSH, " + reg_str(FST, i) + ", "
                                             + reg_str(SND, i) + "),\n";
    END

    /* 32-bit: */
    /* add32 dst src|imm */
    case add32:
      if (ty2 == Immediate)
        c_code += "BPF_ALU32_IMM(BPF_ADD, " + reg_str(FST, i)  + ", "
                                            + STR(val(SND, i)) + "),\n";
      else
        c_code += "BPF_ALU32_REG(BPF_ADD, " + reg_str(FST, i) + ", "
                                            + reg_str(SND, i) + "),\n";
    END

    /* sub32 dst src|imm */
    case sub32:
      if (ty2 == Immediate)
        c_code += "BPF_ALU32_IMM(BPF_SUB, " + reg_str(FST, i)  + ", "
                                            + STR(val(SND, i)) + "),\n";
      else
        c_code += "BPF_ALU32_REG(BPF_SUB, " + reg_str(FST, i) + ", "
                                            + reg_str(SND, i) + "),\n";
    END

    /* mul32 dst src|imm */
    case mul32:
      if (ty2 == Immediate)
        c_code += "BPF_ALU32_IMM(BPF_MUL, " + reg_str(FST, i)  + ", "
                                            + STR(val(SND, i)) + "),\n";
      else
        c_code += "BPF_ALU32_REG(BPF_MUL, " + reg_str(FST, i) + ", "
                                            + reg_str(SND, i) + "),\n";
    END

    /* div32 dst src|imm */
    case div32:
      if (ty2 == Immediate)
        c_code += "BPF_ALU32_IMM(BPF_DIV, " + reg_str(FST, i)  + ", "
                                            + STR(val(SND, i)) + "),\n";
      else
        c_code += "BPF_ALU32_REG(BPF_DIV, " + reg_str(FST, i) + ", "
                                            + reg_str(SND, i) + "),\n";
    END

    /* or32 dst src|imm */
    case or32:
      if (ty2 == Immediate)
        c_code += "BPF_ALU32_IMM(BPF_OR, " + reg_str(FST, i)  + ", "
                                           + STR(val(SND, i)) + "),\n";
      else
        c_code += "BPF_ALU32_REG(BPF_OR, " + reg_str(FST, i) + ", "
                                           + reg_str(SND, i) + "),\n";
    END

    /* and32 dst src|imm */
    case and32:
      if (ty2 == Immediate)
        c_code += "BPF_ALU32_IMM(BPF_AND, " + reg_str(FST, i)  + ", "
                                            + STR(val(SND, i)) + "),\n";
      else
        c_code += "BPF_ALU32_REG(BPF_AND, " + reg_str(FST, i) + ", "
                                            + reg_str(SND, i) + "),\n";
    END

    /* lsh32 dst src|imm */
    case lsh32:
      if (ty2 == Immediate)
        c_code += "BPF_ALU32_IMM(BPF_LSH, " + reg_str(FST, i)  + ", "
                                            + STR(val(SND, i)) + "),\n";
      else
        c_code += "BPF_ALU32_REG(BPF_LSH, " + reg_str(FST, i) + ", "
                                            + reg_str(SND, i) + "),\n";
    END

    /* rsh32 dst src|imm */
    case rsh32:
      if (ty2 == Immediate)
        c_code += "BPF_ALU32_IMM(BPF_RSH, " + reg_str(FST, i)  + ", "
                                            + STR(val(SND, i)) + "),\n";
      else
        c_code += "BPF_ALU32_REG(BPF_RSH, " + reg_str(FST, i) + ", "
                                            + reg_str(SND, i) + "),\n";
    END

    /* neg32 dst */
    case neg32:
       c_code += "BPF_ALU32_IMM(BPF_NEG, " + reg_str(FST, i) + ", 0),\n";
    END

    /* mod32 dst src|imm */
    case mod32:
      if (ty2 == Immediate)
        c_code += "BPF_ALU32_IMM(BPF_MOD, " + reg_str(FST, i)  + ", "
                                            + STR(val(SND, i)) + "),\n";
      else
        c_code += "BPF_ALU32_REG(BPF_MOD, " + reg_str(FST, i) + ", "
                                            + reg_str(SND, i) + "),\n";
    END

    /* xor32 dst src|imm */
    case xor32:
      if (ty2 == Immediate)
        c_code += "BPF_ALU32_IMM(BPF_XOR, " + reg_str(FST, i)  + ", "
                                            + STR(val(SND, i)) + "),\n";
      else
        c_code += "BPF_ALU32_REG(BPF_XOR, " + reg_str(FST, i) + ", "
                                            + reg_str(SND, i) + "),\n";
    END

    /* mov32 dst src|imm */
    case mov32:
      if (ty2 == Immediate)
        c_code += "BPF_ALU32_IMM(BPF_MOV, " + reg_str(FST, i)  + ", "
                                            + STR(val(SND, i)) + "),\n";
      else
        c_code += "BPF_ALU32_REG(BPF_MOV, " + reg_str(FST, i) + ", "
                                            + reg_str(SND, i) + "),\n";
     END

    /* arsh32 dst src|imm */
    case arsh32:
      if (ty2 == Immediate)
        c_code += "BPF_ALU32_IMM(BPF_ARSH, " + reg_str(FST, i)  + ", "
                                             + STR(val(SND, i)) + "),\n";
      else
        c_code += "BPF_ALU32_REG(BPF_ARSH, " + reg_str(FST, i) + ", "
                                             + reg_str(SND, i) + "),\n";
    END

    /* le16 dst src|imm */
    case le16:
       c_code += "BPF_ENDIAN(BPF_TO_LE, " + reg_str(FST, i) + ", 16),\n";
    END

    /* le32 dst src|imm */
    case le32:
       c_code += "BPF_ENDIAN(BPF_TO_LE, " + reg_str(FST, i) + ", 32),\n";
    END

    /* le64 dst src|imm */
    case le64:
       c_code += "BPF_ENDIAN(BPF_TO_LE, " + reg_str(FST, i) + ", 64),\n";
    END

    /* be16 dst src|imm */
    case be16:
       c_code += "BPF_ENDIAN(BPF_TO_BE, " + reg_str(FST, i) + ", 16),\n";
    END

    /* be32 dst src|imm */
    case be32:
       c_code += "BPF_ENDIAN(BPF_TO_BE, " + reg_str(FST, i) + ", 32),\n";
    END

    /* be64 dst src|imm */
    case be64:
       c_code += "BPF_ENDIAN(BPF_TO_BE, " + reg_str(FST, i) + ", 64),\n";
    END

    /* addx16 dst src off */
    case addx16:
       c_code += "BPF_ATOMIC_OP(16, BPF_ADD, "
              +  reg_str(FST, i)         + ", "
              +  reg_str(SND, i)         + ", "
              +  STR((__s16)val(TRD, i)) + "),\n";
    END

    /* addx32 dst src off */
    case addx32:
      c_code += "BPF_ATOMIC_OP(32, BPF_ADD, "
             +  reg_str(FST, i)         + ", "
             +  reg_str(SND, i)         + ", "
             +  STR((__s16)val(TRD, i)) + "),\n";
    END

    /* addx64 dst src off */
    case addx64:
       c_code += "BPF_ATOMIC_OP(64, BPF_ADD, "
              +  reg_str(FST, i)         + ", "
              +  reg_str(SND, i)         + ", "
              +  STR((__s16)val(TRD, i)) + "),\n";
    END

    /* andx16 dst src off */
    case andx16:
       c_code += "BPF_ATOMIC_OP(16, BPF_AND, "
              +  reg_str(FST, i)         + ", "
              +  reg_str(SND, i)         + ", "
              +  STR((__s16)val(TRD, i)) + "),\n";
    END

    /* andx32 dst src off */
    case andx32:
       c_code += "BPF_ATOMIC_OP(32, BPF_AND, "
              +  reg_str(FST, i)         + ", "
              +  reg_str(SND, i)         + ", "
              +  STR((__s16)val(TRD, i)) + "),\n";
    END

    /* andx64 dst src off */
    case andx64:
       c_code += "BPF_ATOMIC_OP(64, BPF_AND, "
              +  reg_str(FST, i)         + ", "
              +  reg_str(SND, i)         + ", "
              +  STR((__s16)val(TRD, i)) + "),\n";
    END

    /* orx16 dst src off */
    case orx16:
       c_code += "BPF_ATOMIC_OP(16, BPF_OR, "
              +  reg_str(FST, i)         + ", "
              +  reg_str(SND, i)         + ", "
              +  STR((__s16)val(TRD, i)) + "),\n";
    END

    /* orx32 dst src off */
    case orx32:
       c_code += "BPF_ATOMIC_OP(32, BPF_OR, "
              +  reg_str(FST, i)         + ", "
              +  reg_str(SND, i)         + ", "
              +  STR((__s16)val(TRD, i)) + "),\n";
    END

    /* orx64 dst src off */
    case orx64:
       c_code += "BPF_ATOMIC_OP(64, BPF_OR, "
              +  reg_str(FST, i)         + ", "
              +  reg_str(SND, i)         + ", "
              +  STR((__s16)val(TRD, i)) + "),\n";
    END

    /* xorx16 dst src off */
    case xorx16:
       c_code += "BPF_ATOMIC_OP(16, BPF_XOR, "
              +  reg_str(FST, i)         + ", "
              +  reg_str(SND, i)         + ", "
              +  STR((__s16)val(TRD, i)) + "),\n";
    END

    /* xorx32 dst src off */
    case xorx32:
       c_code += "BPF_ATOMIC_OP(32, BPF_XOR, "
              +  reg_str(FST, i)         + ", "
              +  reg_str(SND, i)         + ", "
              +  STR((__s16)val(TRD, i)) + "),\n";
    END

    /* xorx64 dst src off */
    case xorx64:
       c_code += "BPF_ATOMIC_OP(64, BPF_XOR, "
              +  reg_str(FST, i)         + ", "
              +  reg_str(SND, i)         + ", "
              +  STR((__s16)val(TRD, i)) + "),\n";
    END

    /* addfx16 dst src off */
    case addfx16:
       c_code += "BPF_ATOMIC_OP(16, BPF_ADD | BPF_FETCH, "
              +  reg_str(FST, i)         + ", "
              +  reg_str(SND, i)         + ", "
              +  STR((__s16)val(TRD, i)) + "),\n";
    END

    /* addfx32 dst src off */
    case addfx32:
       c_code += "BPF_ATOMIC_OP(32, BPF_ADD | BPF_FETCH, "
              +  reg_str(FST, i)         + ", "
              +  reg_str(SND, i)         + ", "
              +  STR((__s16)val(TRD, i)) + "),\n";
    END

    /* addfx64 dst src off */
    case addfx64:
       c_code += "BPF_ATOMIC_OP(64, BPF_ADD | BPF_FETCH, "
              +  reg_str(FST, i)         + ", "
              +  reg_str(SND, i)         + ", "
              +  STR((__s16)val(TRD, i)) + "),\n";
    END

    /* andfx16 dst src off */
    case andfx16:
       c_code += "BPF_ATOMIC_OP(16, BPF_AND | BPF_FETCH, "
              +  reg_str(FST, i)         + ", "
              +  reg_str(SND, i)         + ", "
              +  STR((__s16)val(TRD, i)) + "),\n";
    END

    /* andfx32 dst src off */
    case andfx32:
       c_code += "BPF_ATOMIC_OP(32, BPF_AND | BPF_FETCH, "
              +  reg_str(FST, i)         + ", "
              +  reg_str(SND, i)         + ", "
              +  STR((__s16)val(TRD, i)) + "),\n";
    END

    /* andfx64 dst src off */
    case andfx64:
       c_code += "BPF_ATOMIC_OP(64, BPF_AND | BPF_FETCH, "
              +  reg_str(FST, i)         + ", "
              +  reg_str(SND, i)         + ", "
              +  STR((__s16)val(TRD, i)) + "),\n";
    END

    /* orfx16 dst src off */
    case orfx16:
       c_code += "BPF_ATOMIC_OP(16, BPF_OR | BPF_FETCH, "
              +  reg_str(FST, i)         + ", "
              +  reg_str(SND, i)         + ", "
              +  STR((__s16)val(TRD, i)) + "),\n";
    END

    /* orfx32 dst src off */
    case orfx32:
       c_code += "BPF_ATOMIC_OP(32, BPF_OR | BPF_FETCH, "
              +  reg_str(FST, i)         + ", "
              +  reg_str(SND, i)         + ", "
              +  STR((__s16)val(TRD, i)) + "),\n";
    END

    /* orfx64 dst src off */
    case orfx64:
       c_code += "BPF_ATOMIC_OP(64, BPF_OR | BPF_FETCH, "
              +  reg_str(FST, i)         + ", "
              +  reg_str(SND, i)         + ", "
              +  STR((__s16)val(TRD, i)) + "),\n";
    END

    /* xorfx16 dst src off */
    case xorfx16:
       c_code += "BPF_ATOMIC_OP(16, BPF_XOR | BPF_FETCH, "
              +  reg_str(FST, i)         + ", "
              +  reg_str(SND, i)         + ", "
              +  STR((__s16)val(TRD, i)) + "),\n";
    END

    /* xorfx32 dst src off */
    case xorfx32:
       c_code += "BPF_ATOMIC_OP(32, BPF_XOR | BPF_FETCH, "
              +  reg_str(FST, i)         + ", "
              +  reg_str(SND, i)         + ", "
              +  STR((__s16)val(TRD, i)) + "),\n";
    END

    /* xorfx64 dst src off */
    case xorfx64:
       c_code += "BPF_ATOMIC_OP(64, BPF_XOR | BPF_FETCH, "
              +  reg_str(FST, i)         + ", "
              +  reg_str(SND, i)         + ", "
              +  STR((__s16)val(TRD, i)) + "),\n";
    END

    /* xchgx16 dst src off */
    case xchgx16:
       c_code += "BPF_ATOMIC_OP(16, BPF_XCHG, "
              +  reg_str(FST, i)         + ", "
              +  reg_str(SND, i)         + ", "
              +  STR((__s16)val(TRD, i)) + "),\n";
    END

    /* xchgx32 dst src off */
    case xchgx32:
       c_code += "BPF_ATOMIC_OP(32, BPF_XCHG, "
              +  reg_str(FST, i)         + ", "
              +  reg_str(SND, i)         + ", "
              +  STR((__s16)val(TRD, i)) + "),\n";
    END

    /* xchgx64 dst src off */
    case xchgx64:
       c_code += "BPF_ATOMIC_OP(64, BPF_XCHG, "
              +  reg_str(FST, i)         + ", "
              +  reg_str(SND, i)         + ", "
              +  STR((__s16)val(TRD, i)) + "),\n";
    END

    /* cmpxchgx16 dst src off */
    case cmpxchgx16:
       c_code += "BPF_ATOMIC_OP(16, BPF_CMPXCHG, "
              +  reg_str(FST, i)         + ", "
              +  reg_str(SND, i)         + ", "
              +  STR((__s16)val(TRD, i)) + "),\n";
    END

    /* cmpxchgx32 dst src off */
    case cmpxchgx32:
       c_code += "BPF_ATOMIC_OP(32, BPF_CMPXCHG, "
              +  reg_str(FST, i)         + ", "
              +  reg_str(SND, i)         + ", "
              +  STR((__s16)val(TRD, i)) + "),\n";
    END

    /* cmpxchgx64 dst src off */
    case cmpxchgx64:
       c_code += "BPF_ATOMIC_OP(64, BPF_CMPXCHG, "
              +  reg_str(FST, i)         + ", "
              +  reg_str(SND, i)         + ", "
              +  STR((__s16)val(TRD, i)) + "),\n";
    END

    /* ldmapfd dst imm  */
    case ldmapfd:
      c_code += "BPF_LD_MAP_FD(" + reg_str(FST, i)  + ", "
                                 + STR(val(SND, i)) + "),\n";
    END

    /* ld64 dst imm  */
    case ld64:
      c_code += "BPF_LD_IMM64(" + reg_str(FST, i)  + ", "
                                + STR(val(SND, i)) + "),\n";
    END

    /* ldabs8 imm  */
    case ldabs8:
      c_code += "BPF_LD_ABS(8, " + STR(val(FST, i)) + "),\n";
    END

    /* ldabs16 imm  */
    case ldabs16:
      c_code += "BPF_LD_ABS(16, " + STR(val(FST, i)) + "),\n";
    END

    /* ldabs32 imm  */
    case ldabs32:
      c_code += "BPF_LD_ABS(32, " + STR(val(FST, i)) + "),\n";
    END

    /* ldabs64 imm  */
    case ldabs64:
      c_code += "BPF_LD_ABS(64, " + STR(val(FST, i)) + "),\n";
    END

    /* ldind8 src imm  */
    case ldind8:
       c_code += "BPF_LD_IND(8, " + reg_str(FST, i)  + ", "
                                  + STR(val(SND, i)) + "),\n";
    END

    /* ldind16 src imm  */
    case ldind16:
       c_code += "BPF_LD_IND(16, " + reg_str(FST, i)  + ", "
                                   + STR(val(SND, i)) + "),\n";
    END

    /* ldind32 src imm  */
    case ldind32:
       c_code += "BPF_LD_IND(32, " + reg_str(FST, i)  + ", "
                                   + STR(val(SND, i)) + "),\n";
    END

    /* ldind64 src imm  */
    case ldind64:
       c_code += "BPF_LD_IND(64, " + reg_str(FST, i)  + ", "
                                   + STR(val(SND, i)) + "),\n";
    END

    /* ldx8 dst src off */
    case ldx8:
       c_code += "BPF_LDX_MEM(8, " + reg_str(FST, i)         + ", "
                                   + reg_str(SND, i)         + ", "
                                   + STR((__s16)val(TRD, i)) + "),\n";
    END

    /* ldx16 dst src off */
    case ldx16:
       c_code += "BPF_LDX_MEM(16, " + reg_str(FST, i)         + ", "
                                    + reg_str(SND, i)         + ", "
                                    + STR((__s16)val(TRD, i)) + "),\n";
    END

    /* ldx32 dst src off */
    case ldx32:
       c_code += "BPF_LDX_MEM(32, " + reg_str(FST, i)         + ", "
                                    + reg_str(SND, i)         + ", "
                                    + STR((__s16)val(TRD, i)) + "),\n";
    END

    /* ldx64 dst src off */
    case ldx64:
       c_code += "BPF_LDX_MEM(64, " + reg_str(FST, i)         + ", "
                                    + reg_str(SND, i)         + ", "
                                    + STR((__s16)val(TRD, i)) + "),\n";
    END

    /* st8 dst off imm  */
    case st8:
       c_code += "BPF_ST_MEM(8, " + reg_str(FST, i)         + ", "
                                  + STR((__s16)val(SND, i)) + ", "
                                  + STR(val(TRD, i))        + "),\n";
    END

    /* st16 dst off imm   */
    case st16:
       c_code += "BPF_ST_MEM(16, " + reg_str(FST, i)         + ", "
                                   + STR((__s16)val(SND, i)) + ", "
                                   + STR(val(TRD, i))        + "),\n";
    END

    /* st32 dst off imm   */
    case st32:
       c_code += "BPF_ST_MEM(32, " + reg_str(FST, i)         + ", "
                                   + STR((__s16)val(SND, i)) + ", "
                                   + STR(val(TRD, i))        + "),\n";
    END

    /* st64 dst off imm   */
    case st64:
       c_code += "BPF_ST_MEM(64, " + reg_str(FST, i)         + ", "
                                   + STR((__s16)val(SND, i)) + ", "
                                   + STR(val(TRD, i))        + "),\n";
    END

    /* stx8 dst src off */
    case stx8:
       c_code += "BPF_STX_MEM(8, " + reg_str(FST, i)         + ", "
                                   + reg_str(SND, i)         + ", "
                                   + STR((__s16)val(TRD, i)) + "),\n";
    END

    /* stx16 dst src off */
    case stx16:
       c_code += "BPF_STX_MEM(16, " + reg_str(FST, i)         + ", "
                                    + reg_str(SND, i)         + ", "
                                    + STR((__s16)val(TRD, i)) + "),\n";
    END

    /* stx32 dst src off */
    case stx32:
       c_code += "BPF_STX_MEM(32, " + reg_str(FST, i)         + ", "
                                    + reg_str(SND, i)         + ", "
                                    + STR((__s16)val(TRD, i)) + "),\n";
    END

    /* stx64 dst src off */
    case stx64:
       c_code += "BPF_STX_MEM(64, " + reg_str(FST, i)         + ", "
                                    + reg_str(SND, i)         + ", "
                                    + STR((__s16)val(TRD, i)) + "),\n";
    END

    /* stxx8 dst src off */
    case stxx8:
       c_code += "BPF_STX_XADD(8, " + reg_str(FST, i)         + ", "
                                    + reg_str(SND, i)         + ", "
                                    + STR((__s16)val(TRD, i)) + "),\n";
    END

    /* stxx16 dst src off */
    case stxx16:
       c_code += "BPF_STX_XADD(16, " + reg_str(FST, i)         + ", "
                                     + reg_str(SND, i)         + ", "
                                     + STR((__s16)val(TRD, i)) + "),\n";
    END

    /* stxx32 dst src off */
    case stxx32:
       c_code += "BPF_STX_XADD(32, " + reg_str(FST, i)         + ", "
                                     + reg_str(SND, i)         + ", "
                                     + STR((__s16)val(TRD, i)) + "),\n";
    END

    /* stxx64 dst src off */
    case stxx64:
       c_code += "BPF_STX_XADD(64, " + reg_str(FST, i)         + ", "
                                     + reg_str(SND, i)         + ", "
                                     + STR((__s16)val(TRD, i)) + "),\n";
    END

    /* ja off */
    case ja:
       c_code += "BPF_JMP_A(" + STR((__s16)val(FST, i)) + "),\n";
    END

    /* jeq dst src|imm off */
    case jeq:
      if (ty2 == Immediate)
        c_code += "BPF_JMP_IMM(BPF_JEQ, " + reg_str(FST, i)         + ", "
                                          + STR(val(SND, i))        + ", "
                                          + STR((__s16)val(TRD, i)) + "),\n";
      else
        c_code += "BPF_JMP_REG(BPF_JEQ, " + reg_str(FST, i)         + ", "
                                          + reg_str(SND, i)         + ", "
                                          + STR((__s16)val(TRD, i)) + "),\n";
    END

    /* jgt dst src|imm off */
    case jgt:
      if (ty2 == Immediate)
        c_code += "BPF_JMP_IMM(BPF_JGT, " + reg_str(FST, i)         + ", "
                                          + STR(val(SND, i))        + ", "
                                          + STR((__s16)val(TRD, i)) + "),\n";
      else
        c_code += "BPF_JMP_REG(BPF_JGT, " + reg_str(FST, i)         + ", "
                                          + reg_str(SND, i)         + ", "
                                          + STR((__s16)val(TRD, i)) + "),\n";
    END

    /* jge dst src|imm off */
    case jge:
      if (ty2 == Immediate)
        c_code += "BPF_JMP_IMM(BPF_JGE, " + reg_str(FST, i)         + ", "
                                          + STR(val(SND, i))        + ", "
                                          + STR((__s16)val(TRD, i)) + "),\n";
      else
        c_code += "BPF_JMP_REG(BPF_JGE, " + reg_str(FST, i)         + ", "
                                          + reg_str(SND, i)         + ", "
                                          + STR((__s16)val(TRD, i)) + "),\n";
    END

    /* jlt dst src|imm off */
    case jlt:
      if (ty2 == Immediate)
        c_code += "BPF_JMP_IMM(BPF_JLT, " + reg_str(FST, i)         + ", "
                                          + STR(val(SND, i))        + ", "
                                          + STR((__s16)val(TRD, i)) + "),\n";
      else
        c_code += "BPF_JMP_REG(BPF_JLT, " + reg_str(FST, i)         + ", "
                                          + reg_str(SND, i)         + ", "
                                          + STR((__s16)val(TRD, i)) + "),\n";
    END

    /* jle dst src|imm off */
    case jle:
      if (ty2 == Immediate)
        c_code += "BPF_JMP_IMM(BPF_JLE, " + reg_str(FST, i)         + ", "
                                          + STR(val(SND, i))        + ", "
                                          + STR((__s16)val(TRD, i)) + "),\n";
      else
        c_code += "BPF_JMP_REG(BPF_JLE, " + reg_str(FST, i)         + ", "
                                          + reg_str(SND, i)         + ", "
                                          + STR((__s16)val(TRD, i)) + "),\n";
    END

    /* jset dst src|imm off */
    case jset:
      if (ty2 == Immediate)
        c_code += "BPF_JMP_IMM(BPF_JSET, " + reg_str(FST, i)         + ", "
                                           + STR(val(SND, i))        + ", "
                                           + STR((__s16)val(TRD, i)) + "),\n";
      else
        c_code += "BPF_JMP_REG(BPF_JSET, " + reg_str(FST, i)         + ", "
                                           + reg_str(SND, i)         + ", "
                                           + STR((__s16)val(TRD, i)) + "),\n";
    END

    /* jne dst src|imm off */
    case jne:
      if (ty2 == Immediate)
        c_code += "BPF_JMP_IMM(BPF_JNE, " + reg_str(FST, i)         + ", "
                                          + STR(val(SND, i))        + ", "
                                          + STR((__s16)val(TRD, i)) + "),\n";
      else
        c_code += "BPF_JMP_REG(BPF_JNE, " + reg_str(FST, i)         + ", "
                                          + reg_str(SND, i)         + ", "
                                          + STR((__s16)val(TRD, i)) + "),\n";
    END

    /* jsgt dst src|imm off */
    case jsgt:
      if (ty2 == Immediate)
        c_code += "BPF_JMP_IMM(BPF_JSGT, " + reg_str(FST, i)         + ", "
                                           + STR(val(SND, i))        + ", "
                                           + STR((__s16)val(TRD, i)) + "),\n";
      else
        c_code += "BPF_JMP_REG(BPF_JSGT, " + reg_str(FST, i)         + ", "
                                           + reg_str(SND, i)         + ", "
                                           + STR((__s16)val(TRD, i)) + "),\n";
    END

    /* jsge dst src|imm off */
    case jsge:
      if (ty2 == Immediate)
        c_code += "BPF_JMP_IMM(BPF_JSGE, " + reg_str(FST, i)         + ", "
                                           + STR(val(SND, i))        + ", "
                                           + STR((__s16)val(TRD, i)) + "),\n";
      else
        c_code += "BPF_JMP_REG(BPF_JSGE, " + reg_str(FST, i)         + ", "
                                           + reg_str(SND, i)         + ", "
                                           + STR((__s16)val(TRD, i)) + "),\n";
    END

    /* jslt dst src|imm off */
    case jslt:
      if (ty2 == Immediate)
        c_code += "BPF_JMP_IMM(BPF_JSLT, " + reg_str(FST, i)         + ", "
                                           + STR(val(SND, i))        + ", "
                                           + STR((__s16)val(TRD, i)) + "),\n";
      else
        c_code += "BPF_JMP_REG(BPF_JSLT, " + reg_str(FST, i)         + ", "
                                           + reg_str(SND, i)         + ", "
                                           + STR((__s16)val(TRD, i)) + "),\n";
    END

    /* jsle dst src|imm off */
    case jsle:
      if (ty2 == Immediate)
        c_code += "BPF_JMP_IMM(BPF_JSLE, " + reg_str(FST, i)         + ", "
                                           + STR(val(SND, i))        + ", "
                                           + STR((__s16)val(TRD, i)) + "),\n";
      else
        c_code += "BPF_JMP_REG(BPF_JSLE, " + reg_str(FST, i)         + ", "
                                           + reg_str(SND, i)         + ", "
                                           + STR((__s16)val(TRD, i)) + "),\n";
    END

    /* call imm */
    case call:
      error(ERR_STR "the `call` instruction is not yet supported.");
    END

    /* rel imm */
    case rel:
      c_code += "BPF_CALL_REL(" + STR(val(FST, i)) + "),\n";
    END

    /* exit */
    case exit_:
      c_code += "BPF_EXIT_INSN(),\n";
    END

    /* jeq32 dst src|imm off */
    case jeq32:
      if (ty2 == Immediate)
        c_code += "BPF_JMP32_IMM(BPF_JEQ, " + reg_str(FST, i)         + ", "
                                            + STR(val(SND, i))        + ", "
                                            + STR((__s16)val(TRD, i)) + "),\n";
      else
        c_code += "BPF_JMP32_REG(BPF_JEQ, " + reg_str(FST, i)         + ", "
                                            + reg_str(SND, i)         + ", "
                                            + STR((__s16)val(TRD, i)) + "),\n";
    END

    /* jgt32 dst src|imm off */
    case jgt32:
      if (ty2 == Immediate)
        c_code += "BPF_JMP32_IMM(BPF_JGT, " + reg_str(FST, i)         + ", "
                                            + STR(val(SND, i))        + ", "
                                            + STR((__s16)val(TRD, i)) + "),\n";
      else
        c_code += "BPF_JMP32_REG(BPF_JGT, " + reg_str(FST, i)         + ", "
                                            + reg_str(SND, i)         + ", "
                                            + STR((__s16)val(TRD, i)) + "),\n";
    END

    /* jge32 dst src|imm off */
    case jge32:
      if (ty2 == Immediate)
        c_code += "BPF_JMP32_IMM(BPF_JGE, " + reg_str(FST, i)         + ", "
                                            + STR(val(SND, i))        + ", "
                                            + STR((__s16)val(TRD, i)) + "),\n";
      else
        c_code += "BPF_JMP32_REG(BPF_JGE, " + reg_str(FST, i)         + ", "
                                            + reg_str(SND, i)         + ", "
                                            + STR((__s16)val(TRD, i)) + "),\n";
    END

    /* jlt32 dst src|imm off */
    case jlt32:
      if (ty2 == Immediate)
        c_code += "BPF_JMP32_IMM(BPF_JLT, " + reg_str(FST, i)         + ", "
                                            + STR(val(SND, i))        + ", "
                                            + STR((__s16)val(TRD, i)) + "),\n";
      else
        c_code += "BPF_JMP32_REG(BPF_JLT, " + reg_str(FST, i)         + ", "
                                            + reg_str(SND, i)         + ", "
                                            + STR((__s16)val(TRD, i)) + "),\n";
    END

    /* jle32 dst src|imm off */
    case jle32:
      if (ty2 == Immediate)
        c_code += "BPF_JMP32_IMM(BPF_JLE, " + reg_str(FST, i)         + ", "
                                            + STR(val(SND, i))        + ", "
                                            + STR((__s16)val(TRD, i)) + "),\n";
      else
        c_code += "BPF_JMP32_REG(BPF_JLE, " + reg_str(FST, i)         + ", "
                                            + reg_str(SND, i)         + ", "
                                            + STR((__s16)val(TRD, i)) + "),\n";
    END

    /* jset32 dst src|imm off */
    case jset32:
      if (ty2 == Immediate)
        c_code += "BPF_JMP32_IMM(BPF_JSET, " + reg_str(FST, i)         + ", "
                                             + STR(val(SND, i))        + ", "
                                             + STR((__s16)val(TRD, i)) + "),\n";
      else
        c_code += "BPF_JMP32_REG(BPF_JSET, " + reg_str(FST, i)         + ", "
                                             + reg_str(SND, i)         + ", "
                                             + STR((__s16)val(TRD, i)) + "),\n";
    END

    /* jne32 dst src|imm off */
    case jne32:
      if (ty2 == Immediate)
        c_code += "BPF_JMP32_IMM(BPF_JNE, " + reg_str(FST, i)         + ", "
                                            + STR(val(SND, i))        + ", "
                                            + STR((__s16)val(TRD, i)) + "),\n";
      else
        c_code += "BPF_JMP32_REG(BPF_JNE, " + reg_str(FST, i)         + ", "
                                            + reg_str(SND, i)         + ", "
                                            + STR((__s16)val(TRD, i)) + "),\n";
    END

    /* jsgt32 dst src|imm off */
    case jsgt32:
      if (ty2 == Immediate)
        c_code += "BPF_JMP32_IMM(BPF_JSGT, " + reg_str(FST, i)         + ", "
                                             + STR(val(SND, i))        + ", "
                                             + STR((__s16)val(TRD, i)) + "),\n";
      else
        c_code += "BPF_JMP32_REG(BPF_JSGT, " + reg_str(FST, i)         + ", "
                                             + reg_str(SND, i)         + ", "
                                             + STR((__s16)val(TRD, i)) + "),\n";
    END

    /* jsge32 dst src|imm off */
    case jsge32:
      if (ty2 == Immediate)
        c_code += "BPF_JMP32_IMM(BPF_JSGE, " + reg_str(FST, i)         + ", "
                                             + STR(val(SND, i))        + ", "
                                             + STR((__s16)val(TRD, i)) + "),\n";
      else
        c_code += "BPF_JMP32_REG(BPF_JSGE, " + reg_str(FST, i)         + ", "
                                             + reg_str(SND, i)         + ", "
                                             + STR((__s16)val(TRD, i)) + "),\n";
    END

    /* jslt32 dst src|imm off */
    case jslt32:
      if (ty2 == Immediate)
        c_code += "BPF_JMP32_IMM(BPF_JSLT, " + reg_str(FST, i)         + ", "
                                             + STR(val(SND, i))        + ", "
                                             + STR((__s16)val(TRD, i)) + "),\n";
      else
        c_code += "BPF_JMP32_REG(BPF_JSLT, " + reg_str(FST, i)         + ", "
                                             + reg_str(SND, i)         + ", "
                                             + STR((__s16)val(TRD, i)) + "),\n";
    END

    /* jsle32 dst src|imm off */
    case jsle32:
      if (ty2 == Immediate)
        c_code += "BPF_JMP32_IMM(BPF_JSLE, " + reg_str(FST, i)         + ", "
                                             + STR(val(SND, i))        + ", "
                                             + STR((__s16)val(TRD, i)) + "),\n";
      else
        c_code += "BPF_JMP32_REG(BPF_JSLE, " + reg_str(FST, i)         + ", "
                                             + reg_str(SND, i)         + ", "
                                             + STR((__s16)val(TRD, i)) + "),\n";
    END

    /* zext dst */
    case zext:
      c_code += "BPF_ZEXT_REG(" + reg_str(FST, i) + "),\n";
    END

    _
      error(ERR_STR "code generation: uncovered instruction: `",
            pp_ins(isa(i)), "` categorical variable: ", isa(i));
    END
    }
  }

  c_code += "};\n";

  OFStream ofs;
  ofs.open(out_fname);
  if (!ofs.is_open())
    error(ERR_STR "std::ofstream::open() failed opening file: `", out_fname,
          "`: ", strerror(errno));
  ofs<<c_code;
  ofs.close();
}
