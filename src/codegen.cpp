/*
  Generate object code or C macro preprocessors.
*/
#include <../headers/bpf_insn.h>
#include "codegen.h"

#define HEAD_CSTRUCT "static struct bpf_insn prog[1000000] = {\n"
#define HEAD_FST_CSTRUCT "static struct bpf_insn "
#define HEAD_SND_CSTRUCT "[1000000] = {\n"
#define TAIL_CSTRUCT "\n};\n"

#define MAX_INSNS 1000000

static inline __u8 map_reg(ident_t id) {
  if      (id == "r0")  return BPF_REG_0;
  else if (id == "r1")  return BPF_REG_1;
  else if (id == "r2")  return BPF_REG_2;
  else if (id == "r3")  return BPF_REG_3;
  else if (id == "r4")  return BPF_REG_4;
  else if (id == "r5")  return BPF_REG_5;
  else if (id == "r6")  return BPF_REG_6;
  else if (id == "r7")  return BPF_REG_7;
  else if (id == "r8")  return BPF_REG_8;
  else if (id == "r9")  return BPF_REG_9;
  else if (id == "r10") return BPF_REG_10;
  else error("map_reg(): unknown register ", id);
  return -1;
}

template <typename T>
static inline T get_val(Node n, ident_t id) {
  if      (n == imm_int)   return std::stoi(id);
  else if (n == imm_float) return std::stof(id);
  else error("get_val(): not an immediate: ", pp_subtype(n), ", id: ", id);
  return -1;
}

static inline __u8 get_reg(Node n, ident_t id) {
  if (n == regs) return map_reg(id);
  else error("get_reg(): not a register: ", pp_subtype(n), ", id: ", id);
  return -1;
}

static inline std::string get_reg_str(Node n, ident_t id) {
  if (n != regs)
    error("get_reg_str(): not a register: ", pp_subtype(n));

  if      (id == "r0")  return "BPF_REG_0";
  else if (id == "r1")  return "BPF_REG_1";
  else if (id == "r2")  return "BPF_REG_2";
  else if (id == "r3")  return "BPF_REG_3";
  else if (id == "r4")  return "BPF_REG_4";
  else if (id == "r5")  return "BPF_REG_5";
  else if (id == "r6")  return "BPF_REG_6";
  else if (id == "r7")  return "BPF_REG_7";
  else if (id == "r8")  return "BPF_REG_8";
  else if (id == "r9")  return "BPF_REG_9";
  else if (id == "r10") return "BPF_REG_10";

  error("get_reg_str(): not a register: ", pp_subtype(n), ", id: ", id);
  return "";
}

void codegen(std::string out_fname) {

  uint size;
  ast_t node;
  Node node_v, node_v1, node_v2, node_v3;
  Type type;
  ident_t id1, id2, id3;
  uint i, prog_len, ops;
  // errors reported by valgrind are subdued when assigning a smaller
  // ``prog`` array size.
  struct bpf_insn prog[1000000];

  size     = absyn_tree.size();
  prog_len = 0;

  // suppress -Werror=maybe-uninitialized warnings.
  node_v1 = node_v2 = node_v3 = dead_ins;

  for (i=0; i<size; i++) {
    node   = absyn_tree[i];
    node_v = node.node_v;
    type   = node.type;

    if (type == instr)
      ops = get_ops(node_v);
    else
      ops = 0;

    if (ops == 1) {
      id1     = absyn_tree[i+1].id;
      node_v1 = absyn_tree[i+1].node_v;
    }
    else if (ops == 2) {
      id1     = absyn_tree[i+1].id;
      id2     = absyn_tree[i+2].id;
      node_v1 = absyn_tree[i+1].node_v;
      node_v2 = absyn_tree[i+2].node_v;
    }
    else if (ops == 3) {
      id1     = absyn_tree[i+1].id;
      id2     = absyn_tree[i+2].id;
      id3     = absyn_tree[i+3].id;
      node_v1 = absyn_tree[i+1].node_v;
      node_v2 = absyn_tree[i+2].node_v;
      node_v3 = absyn_tree[i+3].node_v;
    }

    /* ALU instructions: */
    /* 64-bit: */
    /* add dst src|imm */
    if (node_v == add) {
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU64_IMM(BPF_ADD, get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU64_REG(BPF_ADD, get_reg(node_v1, id1),
                                                   get_reg(node_v2, id2));
    }

    /* sub dst src|imm */
    else if (node_v == sub) {
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU64_IMM(BPF_SUB, get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU64_REG(BPF_SUB, get_reg(node_v1, id1),
                                                   get_reg(node_v2, id2));
    }

    /* mul dst src|imm */
    else if (node_v == mul) {
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU64_IMM(BPF_MUL, get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU64_REG(BPF_MUL, get_reg(node_v1, id1),
                                                   get_reg(node_v2, id2));
    }

    /* div dst src|imm */
    else if (node_v == div_ins) {
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU64_IMM(BPF_DIV, get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU64_REG(BPF_DIV, get_reg(node_v1, id1),
                                                   get_reg(node_v2, id2));
    }

    /* or dst src|imm */
    else if (node_v == or_ins) {
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU64_IMM(BPF_OR, get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU64_REG(BPF_OR, get_reg(node_v1, id1),
                                                  get_reg(node_v2, id2));
    }

    /* and dst src|imm */
    else if (node_v == and_ins) {
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU64_IMM(BPF_AND, get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU64_REG(BPF_AND, get_reg(node_v1, id1),
                                                   get_reg(node_v2, id2));
    }

    /* lsh dst src|imm */
    else if (node_v == lsh) {
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU64_IMM(BPF_LSH, get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU64_REG(BPF_LSH, get_reg(node_v1, id1),
                                                   get_reg(node_v2, id2));
    }

    /* rsh dst src|imm */
    else if (node_v == rsh) {
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU64_IMM(BPF_RSH, get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU64_REG(BPF_RSH, get_reg(node_v1, id1),
                                                   get_reg(node_v2, id2));
    }

    /* neg dst src|imm */
    else if (node_v == neg) {
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU64_IMM(BPF_NEG, get_reg(node_v1, id1), 0);
    }

    /* mod dst src|imm */
    else if (node_v == mod) {
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU64_IMM(BPF_MOD, get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU64_REG(BPF_MOD, get_reg(node_v1, id1),
                                                   get_reg(node_v2, id2));
    }

    /* xor dst src|imm */
    else if (node_v == xor_ins) {
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU64_IMM(BPF_XOR, get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU64_REG(BPF_XOR, get_reg(node_v1, id1),
                                                   get_reg(node_v2, id2));
    }

    /* mov dst src|imm */
    else if (node_v == mov) {
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU64_IMM(BPF_MOV, get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU64_REG(BPF_MOV, get_reg(node_v1, id1),
                                                   get_reg(node_v2, id2));
    }

    /* arsh dst src|imm */
    else if (node_v == arsh) {
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU64_IMM(BPF_ARSH, get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU64_REG(BPF_ARSH, get_reg(node_v1, id1),
                                                    get_reg(node_v2, id2));
    }

    /* 32-bit: */
    /* add32 dst src|imm */
    if (node_v == add32) {
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU32_IMM(BPF_ADD, get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU32_REG(BPF_ADD, get_reg(node_v1, id1),
                                                   get_reg(node_v2, id2));
    }

    /* sub32 dst src|imm */
    else if (node_v == sub32) {
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU32_IMM(BPF_SUB, get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU32_REG(BPF_SUB, get_reg(node_v1, id1),
                                                   get_reg(node_v2, id2));
    }

    /* mul32 dst src|imm */
    else if (node_v == mul32) {
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU32_IMM(BPF_MUL, get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU32_REG(BPF_MUL, get_reg(node_v1, id1),
                                                   get_reg(node_v2, id2));
    }

    /* div32 dst src|imm */
    else if (node_v == div32) {
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU32_IMM(BPF_DIV, get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU32_REG(BPF_DIV, get_reg(node_v1, id1),
                                                   get_reg(node_v2, id2));
    }

    /* or32 dst src|imm */
    else if (node_v == or32) {
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU32_IMM(BPF_OR, get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU32_REG(BPF_OR, get_reg(node_v1, id1),
                                                  get_reg(node_v2, id2));
    }

    /* and32 dst src|imm */
    else if (node_v == and32) {
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU32_IMM(BPF_AND, get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU32_REG(BPF_AND, get_reg(node_v1, id1),
                                                   get_reg(node_v2, id2));
    }

    /* lsh32 dst src|imm */
    else if (node_v == lsh32) {
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU32_IMM(BPF_LSH, get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU32_REG(BPF_LSH, get_reg(node_v1, id1),
                                                   get_reg(node_v2, id2));
    }

    /* rsh32 dst src|imm */
    else if (node_v == rsh32) {
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU32_IMM(BPF_RSH, get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU32_REG(BPF_RSH, get_reg(node_v1, id1),
                                                   get_reg(node_v2, id2));
    }

    /* neg32 dst */
    else if (node_v == neg32) {
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU32_IMM(BPF_NEG, get_reg(node_v1, id1), 0);
    }

    /* mod32 dst src|imm */
    else if (node_v == mod32) {
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU32_IMM(BPF_MOD, get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU32_REG(BPF_MOD, get_reg(node_v1, id1),
                                                   get_reg(node_v2, id2));
    }

    /* xor32 dst src|imm */
    else if (node_v == xor32) {
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU32_IMM(BPF_XOR, get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU32_REG(BPF_XOR, get_reg(node_v1, id1),
                                                   get_reg(node_v2, id2));
    }

    /* mov32 dst src|imm */
    else if (node_v == mov32) {
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU32_IMM(BPF_MOV, get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU32_REG(BPF_MOV, get_reg(node_v1, id1),
                                                   get_reg(node_v2, id2));
    }

    /* arsh32 dst src|imm */
    else if (node_v == arsh32) {
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU32_IMM(BPF_ARSH, get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU32_REG(BPF_ARSH, get_reg(node_v1, id1),
                                                    get_reg(node_v2, id2));
    }

    /* mov32 dst src|imm */
    else if (node_v == mov32) {
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_MOV32_IMM(get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
        prog[prog_len++] = BPF_MOV32_REG(get_reg(node_v1, id1),
                                         get_reg(node_v2, id2));
    }

    /* Endianess conversion (Byteswap) instructions: */
    /* le16 dst */
    else if (node_v == le16) {
      prog[prog_len++] = BPF_ENDIAN(BPF_TO_LE, get_reg(node_v1, id1), 16);
    }

    /* le32 dst */
    else if (node_v == le32) {
      prog[prog_len++] = BPF_ENDIAN(BPF_TO_LE, get_reg(node_v1, id1), 32);
    }

    /* le64 dst */
    else if (node_v == le64) {
      prog[prog_len++] = BPF_ENDIAN(BPF_TO_LE, get_reg(node_v1, id1), 64);
    }

    /* be16 dst */
    else if (node_v == be16) {
      prog[prog_len++] = BPF_ENDIAN(BPF_TO_BE, get_reg(node_v1, id1), 16);
    }

    /* be32 dst */
    else if (node_v == be32) {
      prog[prog_len++] = BPF_ENDIAN(BPF_TO_BE, get_reg(node_v1, id1), 32);
    }

    /* be64 dst */
    else if (node_v == be64) {
      prog[prog_len++] = BPF_ENDIAN(BPF_TO_BE, get_reg(node_v1, id1), 64);
    }

    /* Atomic operations: */
    /* addx16 dst src off */
    else if (node_v == addx16) {
      prog[prog_len++] = BPF_ATOMIC_OP(16, BPF_ADD,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    }

    /* addx32 dst src off */
    else if (node_v == addx32) {
      prog[prog_len++] = BPF_ATOMIC_OP(32, BPF_ADD,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    }

    /* addx64 dst src off */
    else if (node_v == addx64) {
      prog[prog_len++] = BPF_ATOMIC_OP(64, BPF_ADD,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    }

    /* andx16 dst src off */
    else if (node_v == andx16) {
      prog[prog_len++] = BPF_ATOMIC_OP(16, BPF_AND,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    }

    /* andx32 dst src off */
    else if (node_v == andx32) {
      prog[prog_len++] = BPF_ATOMIC_OP(32, BPF_AND,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    }

    /* andx64 dst src off */
    else if (node_v == andx64) {
      prog[prog_len++] = BPF_ATOMIC_OP(64, BPF_AND,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    }

    /* orx16 dst src off */
    else if (node_v == orx16) {
      prog[prog_len++] = BPF_ATOMIC_OP(16, BPF_OR,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    }

    /* orx32 dst src off */
    else if (node_v == orx32) {
      prog[prog_len++] = BPF_ATOMIC_OP(32, BPF_OR,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    }

    /* orx64 dst src off */
    else if (node_v == orx64) {
      prog[prog_len++] = BPF_ATOMIC_OP(64, BPF_OR,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    }

    /* xorx16 dst src off */
    else if (node_v == xorx16) {
      prog[prog_len++] = BPF_ATOMIC_OP(16, BPF_XOR,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    }

    /* xorx32 dst src off */
    else if (node_v == xorx32) {
      prog[prog_len++] = BPF_ATOMIC_OP(32, BPF_XOR,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    }

    /* xorx64 dst src off */
    else if (node_v == xorx64) {
      prog[prog_len++] = BPF_ATOMIC_OP(64, BPF_XOR,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    }

    /* addfx16 dst src off */
    else if (node_v == addfx16) {
      prog[prog_len++] = BPF_ATOMIC_OP(16, BPF_ADD | BPF_FETCH,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    }

    /* addfx32 dst src off */
    else if (node_v == addfx32) {
      prog[prog_len++] = BPF_ATOMIC_OP(32, BPF_ADD | BPF_FETCH,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    }

    /* addfx64 dst src off */
    else if (node_v == addfx64) {
      prog[prog_len++] = BPF_ATOMIC_OP(64, BPF_ADD | BPF_FETCH,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    }

    /* andfx16 dst src off */
    else if (node_v == andfx16) {
      prog[prog_len++] = BPF_ATOMIC_OP(16, BPF_AND | BPF_FETCH,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    }

    /* andfx32 dst src off */
    else if (node_v == andfx32) {
      prog[prog_len++] = BPF_ATOMIC_OP(32, BPF_AND | BPF_FETCH,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    }

    /* andfx64 dst src off */
    else if (node_v == andfx64) {
      prog[prog_len++] = BPF_ATOMIC_OP(64, BPF_AND | BPF_FETCH,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    }

    /* orfx16 dst src off */
    else if (node_v == orfx16) {
      prog[prog_len++] = BPF_ATOMIC_OP(16, BPF_OR | BPF_FETCH,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    }

    /* orfx32 dst src off */
    else if (node_v == orfx32) {
      prog[prog_len++] = BPF_ATOMIC_OP(32, BPF_OR | BPF_FETCH,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    }

    /* orfx64 dst src off */
    else if (node_v == orfx64) {
      prog[prog_len++] = BPF_ATOMIC_OP(64, BPF_OR | BPF_FETCH,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    }

    /* xorfx16 dst src off */
    else if (node_v == xorfx16) {
      prog[prog_len++] = BPF_ATOMIC_OP(16, BPF_XOR | BPF_FETCH,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    }

    /* xorfx32 dst src off */
    else if (node_v == xorfx32) {
      prog[prog_len++] = BPF_ATOMIC_OP(32, BPF_XOR | BPF_FETCH,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    }

    /* xorfx64 dst src off */
    else if (node_v == xorfx64) {
      prog[prog_len++] = BPF_ATOMIC_OP(64, BPF_XOR | BPF_FETCH,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    }

    /* xchgx16 dst src off */
    else if (node_v == xchgx16) {
      prog[prog_len++] = BPF_ATOMIC_OP(16, BPF_XCHG,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    }

    /* xchgx32 dst src off */
    else if (node_v == xchgx32) {
      prog[prog_len++] = BPF_ATOMIC_OP(32, BPF_XCHG,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    }

    /* xchgx64 dst src off */
    else if (node_v == xchgx64) {
      prog[prog_len++] = BPF_ATOMIC_OP(64, BPF_XCHG,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    }

    /* cmpxchgx16 dst src off */
    else if (node_v == cmpxchgx16) {
      prog[prog_len++] = BPF_ATOMIC_OP(16, BPF_CMPXCHG,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    }

    /* cmpxchgx32 dst src off */
    else if (node_v == cmpxchgx32) {
      prog[prog_len++] = BPF_ATOMIC_OP(32, BPF_CMPXCHG,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    }

    /* cmpxchgx64 dst src off */
    else if (node_v == cmpxchgx64) {
      prog[prog_len++] = BPF_ATOMIC_OP(64, BPF_CMPXCHG,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    }

    /* ldmapfd dst imm */
    else if (node_v == ldmapfd) {
      prog[prog_len++] = BPF_LD_MAP_FD(get_reg(node_v1, id1),
                                       get_val<int>(node_v2, id2));
    }

    /* ld64 dst imm */
    else if (node_v == ld64) {
      prog[prog_len++] = BPF_LD_IMM64(get_reg(node_v1, id1),
                                      get_val<int>(node_v2, id2));
    }

    /* ldabs8 imm */
    else if (node_v == ldabs8) {
      prog[prog_len++] = BPF_LD_ABS(8, get_val<int>(node_v1, id1));
    }

    /* ldabs16 imm */
    else if (node_v == ldabs16) {
      prog[prog_len++] = BPF_LD_ABS(16, get_val<int>(node_v1, id1));
    }

    /* ldabs32 imm */
    else if (node_v == ldabs32) {
      prog[prog_len++] = BPF_LD_ABS(32, get_val<int>(node_v1, id1));
    }

    /* ldabs64 imm */
    else if (node_v == ldabs64) {
      prog[prog_len++] = BPF_LD_ABS(64, get_val<int>(node_v1, id1));
    }

    /* ldind8 src imm */
    else if (node_v == ldind8) {
      prog[prog_len++] =
        BPF_LD_IND(8, get_reg(node_v1, id1), get_val<int>(node_v2, id2));
    }

    /* ldind16 src imm */
    else if (node_v == ldind16) {
      prog[prog_len++] =
        BPF_LD_IND(16, get_reg(node_v1, id1), get_val<int>(node_v2, id2));
    }


    /* ldind32 src imm */
    else if (node_v == ldind32) {
      prog[prog_len++] =
        BPF_LD_IND(32, get_reg(node_v1, id1), get_val<int>(node_v2, id2));
    }


    /* ldind64 src imm */
    else if (node_v == ldind64) {
      prog[prog_len++] =
        BPF_LD_IND(64, get_reg(node_v1, id1), get_val<int>(node_v2, id2));
    }


    /* ldx8 dst src off */
    else if (node_v == ldx8) {
      prog[prog_len++] =
        BPF_LDX_MEM(8, get_reg(node_v1, id1), get_reg(node_v2, id2),
                    (__s16)get_val<int>(node_v3, id3));
    }

    /* ldx16 dst src off */
    else if (node_v == ldx16) {
      prog[prog_len++] =
        BPF_LDX_MEM(16, get_reg(node_v1, id1), get_reg(node_v2, id2),
                    (__s16)get_val<int>(node_v3, id3));
    }

    /* ldx32 dst src off */
    else if (node_v == ldx32) {
      prog[prog_len++] =
        BPF_LDX_MEM(32, get_reg(node_v1, id1), get_reg(node_v2, id2),
                    (__s16)get_val<int>(node_v3, id3));
    }

    /* ldx64 dst src off */
    else if (node_v == ldx64) {
      prog[prog_len++] =
        BPF_LDX_MEM(64, get_reg(node_v1, id1), get_reg(node_v2, id2),
                    (__s16)get_val<int>(node_v3, id3));
    }

    /* st8 dst off imm */
    else if (node_v == st8) {
      prog[prog_len++] =
        BPF_ST_MEM(8, get_reg(node_v1, id1), (__s16)get_val<int>(node_v2, id2),
                   get_val<int>(node_v2, id2));
    }

    /* st16 dst off imm */
    else if (node_v == st16) {
      prog[prog_len++] =
        BPF_ST_MEM(16, get_reg(node_v1, id1), (__s16)get_val<int>(node_v2, id2),
                   get_val<int>(node_v2, id2));
    }

    /* st32 dst off imm */
    else if (node_v == st32) {
      prog[prog_len++] =
        BPF_ST_MEM(32, get_reg(node_v1, id1), (__s16)get_val<int>(node_v2, id2),
                   get_val<int>(node_v2, id2));
    }

    /* st64 dst off imm */
    else if (node_v == st64) {
      prog[prog_len++] =
        BPF_ST_MEM(64, get_reg(node_v1, id1), (__s16)get_val<int>(node_v2, id2),
                   get_val<int>(node_v2, id2));
    }

    /* stx8 dst src off */
    else if (node_v == stx8) {
      prog[prog_len++] =
        BPF_STX_MEM(8, get_reg(node_v1, id1), get_reg(node_v2, id2),
                    (__s16)get_val<int>(node_v3, id3));
    }

    /* stx16 dst src off */
    else if (node_v == stx16) {
      prog[prog_len++] =
        BPF_STX_MEM(16, get_reg(node_v1, id1), get_reg(node_v2, id2),
                    (__s16)get_val<int>(node_v3, id3));
    }

    /* stx32 dst src off */
    else if (node_v == stx32) {
      prog[prog_len++] =
        BPF_STX_MEM(32, get_reg(node_v1, id1), get_reg(node_v2, id2),
                    (__s16)get_val<int>(node_v3, id3));
    }

    /* stx64 dst src off */
    else if (node_v == stx64) {
      prog[prog_len++] =
        BPF_STX_MEM(64, get_reg(node_v1, id1), get_reg(node_v2, id2),
                    (__s16)get_val<int>(node_v3, id3));
    }

    /* stxx8 dst src off */
    else if (node_v == stxx8) {
      prog[prog_len++] =
        BPF_STX_XADD(8, get_reg(node_v1, id1), get_reg(node_v2, id2),
                     (__s16)get_val<int>(node_v3, id3));
    }

    /* stxx16 dst src off */
    else if (node_v == stxx16) {
      prog[prog_len++] =
        BPF_STX_XADD(16, get_reg(node_v1, id1), get_reg(node_v2, id2),
                     (__s16)get_val<int>(node_v3, id3));
    }

    /* stxx32 dst src off */
    else if (node_v == stxx32) {
      prog[prog_len++] =
        BPF_STX_XADD(32, get_reg(node_v1, id1), get_reg(node_v2, id2),
                     (__s16)get_val<int>(node_v3, id3));
    }

    /* stxx64 dst src off */
    else if (node_v == stxx64) {
      prog[prog_len++] =
        BPF_STX_XADD(64, get_reg(node_v1, id1), get_reg(node_v2, id2),
                     (__s16)get_val<int>(node_v3, id3));
    }

    /* Branch instructions: */
    /* 64-bit: */

    /* ja off */
    else if (node_v == ja) {
      prog[prog_len++] = BPF_JMP_A((__s16)get_val<int>(node_v1, id1));
    }

    /* jeq dst src|imm off */
    else if (node_v == jeq) {
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP_IMM(BPF_JEQ, get_reg(node_v1, id1),
                       get_val<int>(node_v2, id2),
                       (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP_REG(BPF_JEQ, get_reg(node_v1, id1), get_reg(node_v2, id2),
                      (__s16)get_val<int>(node_v3, id3));
    }

    /* jgt dst src|imm off */
    else if (node_v == jgt) {
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP_IMM(BPF_JGT, get_reg(node_v1, id1),
                       get_val<int>(node_v2, id2),
                       (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP_REG(BPF_JGT, get_reg(node_v1, id1), get_reg(node_v2, id2),
                      (__s16)get_val<int>(node_v3, id3));
    }

    /* jge dst src|imm off */
    else if (node_v == jge) {
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP_IMM(BPF_JGE, get_reg(node_v1, id1),
                       get_val<int>(node_v2, id2),
                       (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP_REG(BPF_JGE, get_reg(node_v1, id1), get_reg(node_v2, id2),
                      (__s16)get_val<int>(node_v3, id3));
    }

    /* jlt dst src|imm off */
    else if (node_v == jlt) {
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP_IMM(BPF_JLT, get_reg(node_v1, id1),
                       get_val<int>(node_v2, id2),
                       (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP_REG(BPF_JLT, get_reg(node_v1, id1), get_reg(node_v2, id2),
                      (__s16)get_val<int>(node_v3, id3));
    }

    /* jle dst src|imm off */
    else if (node_v == jle) {
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP_IMM(BPF_JLE, get_reg(node_v1, id1),
                       get_val<int>(node_v2, id2),
                       (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP_REG(BPF_JLE, get_reg(node_v1, id1),
                      get_reg(node_v2, id2),
                      (__s16)get_val<int>(node_v3, id3));
    }

    /* jset dst src|imm off */
    else if (node_v == jset) {
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP_IMM(BPF_JSET, get_reg(node_v1, id1),
                       get_val<int>(node_v2, id2),
                       (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP_REG(BPF_JSET, get_reg(node_v1, id1), get_reg(node_v2, id2),
                      (__s16)get_val<int>(node_v3, id3));
    }

    /* jne dst src|imm off */
    else if (node_v == jne) {
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP_IMM(BPF_JNE, get_reg(node_v1, id1),
                       get_val<int>(node_v2, id2),
                       (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP_REG(BPF_JNE, get_reg(node_v1, id1), get_reg(node_v2, id2),
                      (__s16)get_val<int>(node_v3, id3));
    }

    /* jsgt dst src|imm off */
    else if (node_v == jsgt) {
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP_IMM(BPF_JSGT, get_reg(node_v1, id1),
                       get_val<int>(node_v2, id2),
                       (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP_REG(BPF_JSGT, get_reg(node_v1, id1), get_reg(node_v2, id2),
                      (__s16)get_val<int>(node_v3, id3));
    }

    /* jsge dst src|imm off */
    else if (node_v == jsge) {
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP_IMM(BPF_JSGE, get_reg(node_v1, id1),
                       get_val<int>(node_v2, id2),
                       (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP_REG(BPF_JSGE, get_reg(node_v1, id1), get_reg(node_v2, id2),
                      (__s16)get_val<int>(node_v3, id3));
    }

    /* jslt dst src|imm off */
    else if (node_v == jslt) {
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP_IMM(BPF_JSLT, get_reg(node_v1, id1),
                       get_val<int>(node_v2, id2),
                       (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP_REG(BPF_JSLT, get_reg(node_v1, id1), get_reg(node_v2, id2),
                      (__s16)get_val<int>(node_v3, id3));
    }

    /* jsle dst src|imm off */
    else if (node_v == jsle) {
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP_IMM(BPF_JSLE, get_reg(node_v1, id1),
                       get_val<int>(node_v2, id2),
                       (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP_REG(BPF_JSLE, get_reg(node_v1, id1), get_reg(node_v2, id2),
                      (__s16)get_val<int>(node_v3, id3));
    }

    /* call imm */
    else if (node_v == call) {
      error("error: call: instruction not yet supported.");
    }

    /* rel imm */
    else if (node_v == rel) {
      prog[prog_len++] = BPF_CALL_REL(get_val<int>(node_v1, id1));
    }

    /* exit */
    else if (node_v == exit_ins) {
      prog[prog_len++] = BPF_EXIT_INSN();
    }

    /* 32-bit: */

    /* jeq32 dst src|imm off */
    else if (node_v == jeq32) {
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP32_IMM(BPF_JEQ, get_reg(node_v1, id1),
                         get_val<int>(node_v2, id2),
                         (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP32_REG(BPF_JEQ, get_reg(node_v1, id1), get_reg(node_v2, id2),
                        (__s16)get_val<int>(node_v3, id3));
    }

    /* jgt32 dst src|imm off */
    else if (node_v == jgt32) {
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP32_IMM(BPF_JGT, get_reg(node_v1, id1),
                         get_val<int>(node_v2, id2),
                         (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP32_REG(BPF_JGT, get_reg(node_v1, id1), get_reg(node_v2, id2),
                        (__s16)get_val<int>(node_v3, id3));
    }

    /* jge32 dst src|imm off */
    else if (node_v == jge32) {
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP32_IMM(BPF_JGE, get_reg(node_v1, id1),
                         get_val<int>(node_v2, id2),
                         (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP32_REG(BPF_JGE, get_reg(node_v1, id1), get_reg(node_v2, id2),
                        (__s16)get_val<int>(node_v3, id3));
    }

    /* jlt32 dst src|imm off */
    else if (node_v == jlt32) {
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP32_IMM(BPF_JLT, get_reg(node_v1, id1),
                         get_val<int>(node_v2, id2),
                         (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP32_REG(BPF_JLT, get_reg(node_v1, id1), get_reg(node_v2, id2),
                        (__s16)get_val<int>(node_v3, id3));
    }

    /* jle32 dst src|imm off */
    else if (node_v == jle32) {
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP32_IMM(BPF_JLE, get_reg(node_v1, id1),
                         get_val<int>(node_v2, id2),
                         (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP32_REG(BPF_JLE, get_reg(node_v1, id1), get_reg(node_v2, id2),
                        (__s16)get_val<int>(node_v3, id3));
    }

    /* jset32 dst src|imm off */
    else if (node_v == jset32) {
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP32_IMM(BPF_JSET, get_reg(node_v1, id1),
                         get_val<int>(node_v2, id2),
                         (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP32_REG(BPF_JSET, get_reg(node_v1, id1), get_reg(node_v2, id2),
                        (__s16)get_val<int>(node_v3, id3));
    }

    /* jne32 dst src|imm off */
    else if (node_v == jne32) {
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP32_IMM(BPF_JNE, get_reg(node_v1, id1),
                         get_val<int>(node_v2, id2),
                         (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP32_REG(BPF_JNE, get_reg(node_v1, id1), get_reg(node_v2, id2),
                        (__s16)get_val<int>(node_v3, id3));
    }

    /* jsgt32 dst src|imm off */
    else if (node_v == jsgt32) {
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP32_IMM(BPF_JSGT, get_reg(node_v1, id1),
                         get_val<int>(node_v2, id2),
                         (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP32_REG(BPF_JSGT, get_reg(node_v1, id1), get_reg(node_v2, id2),
                        (__s16)get_val<int>(node_v3, id3));
    }

    /* jsge32 dst src|imm off */
    else if (node_v == jsge32) {
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP32_IMM(BPF_JSGE, get_reg(node_v1, id1),
                         get_val<int>(node_v2, id2),
                         (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP32_REG(BPF_JSGE, get_reg(node_v1, id1), get_reg(node_v2, id2),
                        (__s16)get_val<int>(node_v3, id3));
    }

    /* jslt32 dst src|imm off */
    else if (node_v == jslt32) {
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP32_IMM(BPF_JSLT, get_reg(node_v1, id1),
                         get_val<int>(node_v2, id2),
                         (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP32_REG(BPF_JSLT, get_reg(node_v1, id1), get_reg(node_v2, id2),
                        (__s16)get_val<int>(node_v3, id3));
    }

    /* jsle32 dst src|imm off */
    else if (node_v == jsle32) {
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP32_IMM(BPF_JSLE, get_reg(node_v1, id1),
                         get_val<int>(node_v2, id2),
                         (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP32_REG(BPF_JSLE, get_reg(node_v1, id1), get_reg(node_v2, id2),
                        (__s16)get_val<int>(node_v3, id3));
    }

    else if (node_v == zext) {
      prog[prog_len++] = BPF_ZEXT_REG(get_reg(node_v1, id1));
    }

  }

  int fd = open(out_fname.c_str(),
                O_CREAT | O_WRONLY | O_TRUNC, S_IREAD | S_IWUSR);
  if (fd == -1)
    error("open() failed on ", out_fname.c_str(), " with log:\n",
          strerror(errno));
  write(fd, prog, prog_len * sizeof(struct bpf_insn));
  close(fd);

}

void codegen_str(std::string out_fname, std::string struct_name) {
  uint size, i, ops;
  ast_t node;
  Node node_v, node_v1, node_v2, node_v3;
  ident_t id1, id2, id3;
  Type type;
  std::string c_code;

  if (struct_name.size())
    c_code += HEAD_FST_CSTRUCT + struct_name + HEAD_SND_CSTRUCT;
  else
    c_code += HEAD_CSTRUCT;

  size = absyn_tree.size();

  // suppress -Werror=maybe-uninitialized warnings.
  node_v1 = node_v2 = node_v3 = dead_ins;

  for (i=0; i<size; i++) {
    node   = absyn_tree[i];
    node_v = node.node_v;
    type   = node.type;

    if (type == instr)
      ops = get_ops(node_v);
    else
      ops = 0;

    if (ops == 1) {
      id1     = absyn_tree[i+1].id;
      node_v1 = absyn_tree[i+1].node_v;
    }
    else if (ops == 2) {
      id1     = absyn_tree[i+1].id;
      id2     = absyn_tree[i+2].id;
      node_v1 = absyn_tree[i+1].node_v;
      node_v2 = absyn_tree[i+2].node_v;
    }
    else if (ops == 3) {
      id1     = absyn_tree[i+1].id;
      id2     = absyn_tree[i+2].id;
      id3     = absyn_tree[i+3].id;
      node_v1 = absyn_tree[i+1].node_v;
      node_v2 = absyn_tree[i+2].node_v;
      node_v3 = absyn_tree[i+3].node_v;
    }

    /* ALU instructions: */
    /* 64-bit: */
    /* add dst src|imm */
    if (node_v == add) {
      if (node_v2 == imm_int)
        c_code += "BPF_ALU64_IMM(BPF_ADD, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU64_REG(BPF_ADD, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + "),\n";
    }

    /* sub dst src|imm */
    else if (node_v == sub) {
      if (node_v2 == imm_int)
        c_code += "BPF_ALU64_IMM(BPF_SUB, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU64_REG(BPF_SUB, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + "),\n";
    }

    /* mul dst src|imm */
    else if (node_v == mul) {
      if (node_v2 == imm_int)
        c_code += "BPF_ALU64_IMM(BPF_MUL, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU64_REG(BPF_MUL, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + "),\n";
    }

    /* div dst src|imm */
    else if (node_v == div_ins) {
      if (node_v2 == imm_int)
        c_code += "BPF_ALU64_IMM(BPF_DIV, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU64_REG(BPF_DIV, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + "),\n";
    }

    /* or dst src|imm */
    else if (node_v == or_ins) {
      if (node_v2 == imm_int)
        c_code += "BPF_ALU64_IMM(BPF_OR, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU64_REG(BPF_OR, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + "),\n";
    }

    /* and dst src|imm */
    else if (node_v == and_ins) {
      if (node_v2 == imm_int)
        c_code += "BPF_ALU64_IMM(BPF_AND, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU64_REG(BPF_AND, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + "),\n";
    }

    /* lsh dst src|imm */
    else if (node_v == lsh) {
      if (node_v2 == imm_int)
        c_code += "BPF_ALU64_IMM(BPF_LSH, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU64_REG(BPF_LSH, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + "),\n";
    }

    /* rsh dst src|imm */
    else if (node_v == rsh) {
      if (node_v2 == imm_int)
        c_code += "BPF_ALU64_IMM(BPF_RSH, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU64_REG(BPF_RSH, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + "),\n";
    }

    /* neg dst src|imm */
    else if (node_v == neg) {
       c_code += "BPF_ALU64_REG(BPF_NEG, " + get_reg_str(node_v1, id1)
                  + ", 0),\n";
    }

    /* mod dst src|imm */
    else if (node_v == mod) {
      if (node_v2 == imm_int)
        c_code += "BPF_ALU64_IMM(BPF_MOD, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU64_REG(BPF_MOD, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + "),\n";
    }

    /* xor dst src|imm */
    else if (node_v == xor_ins) {
      if (node_v2 == imm_int)
        c_code += "BPF_ALU64_IMM(BPF_XOR, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU64_REG(BPF_XOR, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + "),\n";
    }

    /* mov dst src|imm */
    else if (node_v == mov) {
      if (node_v2 == imm_int)
        c_code += "BPF_ALU64_IMM(BPF_MOV, " + get_reg_str(node_v1, id1) + ", "
                   + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
        c_code += "BPF_ALU64_REG(BPF_MOV, " + get_reg_str(node_v1, id1) + ", "
                  + get_reg_str(node_v2, id2) + "),\n";
     }

    /* arsh dst src|imm */
    else if (node_v == arsh) {
      if (node_v2 == imm_int)
        c_code += "BPF_ALU64_IMM(BPF_ARSH, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU64_REG(BPF_ARSH, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + "),\n";
    }

    /* 32-bit: */
    /* add32 dst src|imm */
    if (node_v == add32) {
      if (node_v2 == imm_int)
        c_code += "BPF_ALU32_IMM(BPF_ADD, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU32_REG(BPF_ADD, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + "),\n";
    }

    /* sub32 dst src|imm */
    else if (node_v == sub32) {
      if (node_v2 == imm_int)
        c_code += "BPF_ALU32_IMM(BPF_SUB, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU32_REG(BPF_SUB, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + "),\n";
    }

    /* mul32 dst src|imm */
    else if (node_v == mul32) {
      if (node_v2 == imm_int)
        c_code += "BPF_ALU32_IMM(BPF_MUL, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU32_REG(BPF_MUL, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + "),\n";
    }

    /* div32 dst src|imm */
    else if (node_v == div32) {
      if (node_v2 == imm_int)
        c_code += "BPF_ALU32_IMM(BPF_DIV, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU32_REG(BPF_DIV, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + "),\n";
    }

    /* or32 dst src|imm */
    else if (node_v == or32) {
      if (node_v2 == imm_int)
        c_code += "BPF_ALU32_IMM(BPF_OR, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU32_REG(BPF_OR, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + "),\n";
    }

    /* and32 dst src|imm */
    else if (node_v == and32) {
      if (node_v2 == imm_int)
        c_code += "BPF_ALU32_IMM(BPF_AND, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU32_REG(BPF_AND, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + "),\n";
    }

    /* lsh32 dst src|imm */
    else if (node_v == lsh32) {
      if (node_v2 == imm_int)
        c_code += "BPF_ALU32_IMM(BPF_LSH, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU32_REG(BPF_LSH, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + "),\n";
    }

    /* rsh32 dst src|imm */
    else if (node_v == rsh32) {
      if (node_v2 == imm_int)
        c_code += "BPF_ALU32_IMM(BPF_RSH, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU32_REG(BPF_RSH, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + "),\n";
    }

    /* neg32 dst src|imm */
    else if (node_v == neg32) {
       c_code += "BPF_ALU32_REG(BPF_NEG, " + get_reg_str(node_v1, id1)
                 + ", 0),\n";
    }

    /* mod32 dst src|imm */
    else if (node_v == mod32) {
      if (node_v2 == imm_int)
        c_code += "BPF_ALU32_IMM(BPF_MOD, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU32_REG(BPF_MOD, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + "),\n";
    }

    /* xor32 dst src|imm */
    else if (node_v == xor32) {
      if (node_v2 == imm_int)
        c_code += "BPF_ALU32_IMM(BPF_XOR, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU32_REG(BPF_XOR, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + "),\n";
    }

    /* mov32 dst src|imm */
    else if (node_v == mov32) {
      if (node_v2 == imm_int)
        c_code += "BPF_ALU32_IMM(BPF_MOV, " + get_reg_str(node_v1, id1) + ", "
                   + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
        c_code += "BPF_ALU32_REG(BPF_MOV, " + get_reg_str(node_v1, id1) + ", "
                  + get_reg_str(node_v2, id2) + "),\n";
     }

    /* arsh32 dst src|imm */
    else if (node_v == arsh32) {
      if (node_v2 == imm_int)
        c_code += "BPF_ALU32_IMM(BPF_ARSH, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU32_REG(BPF_ARSH, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + "),\n";
    }

    /* le16 dst src|imm */
    else if (node_v == le16) {
       c_code += "BPF_ENDIAN(BPF_TO_LE, " + get_reg_str(node_v1, id1)
                 + ", 16),\n";
    }

    /* le32 dst src|imm */
    else if (node_v == le32) {
       c_code += "BPF_ENDIAN(BPF_TO_LE, " + get_reg_str(node_v1, id1)
                 + ", 32),\n";
    }

    /* le64 dst src|imm */
    else if (node_v == le64) {
       c_code += "BPF_ENDIAN(BPF_TO_LE, " + get_reg_str(node_v1, id1)
                 + ", 64),\n";
    }

    /* be16 dst src|imm */
    else if (node_v == be16) {
       c_code += "BPF_ENDIAN(BPF_TO_BE, " + get_reg_str(node_v1, id1)
                 + ", 16),\n";
    }

    /* be32 dst src|imm */
    else if (node_v == be32) {
       c_code += "BPF_ENDIAN(BPF_TO_BE, " + get_reg_str(node_v1, id1)
                 + ", 32),\n";
    }

    /* be64 dst src|imm */
    else if (node_v == be64) {
       c_code += "BPF_ENDIAN(BPF_TO_BE, " + get_reg_str(node_v1, id1)
                 + ", 64),\n";
    }

    /* addx16 dst src off */
    else if (node_v == addx16) {
       c_code += "BPF_ATOMIC_OP(16, BPF_ADD, " + get_reg_str(node_v1, id1) +
                 ", " + get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* addx32 dst src off */
    else if (node_v == addx32) {
       c_code += "BPF_ATOMIC_OP(32, BPF_ADD, " + get_reg_str(node_v1, id1) +
                 ", " + get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* addx64 dst src off */
    else if (node_v == addx64) {
       c_code += "BPF_ATOMIC_OP(64, BPF_ADD, " + get_reg_str(node_v1, id1) +
                 ", " + get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* andx16 dst src off */
    else if (node_v == andx16) {
       c_code += "BPF_ATOMIC_OP(16, BPF_AND, " + get_reg_str(node_v1, id1) +
                 ", " +  get_reg_str(node_v2, id2) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3))  + "),\n";
    }

    /* andx32 dst src off */
    else if (node_v == andx32) {
       c_code += "BPF_ATOMIC_OP(32, BPF_AND, " + get_reg_str(node_v1, id1) +
                 ", " + get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* andx64 dst src off */
    else if (node_v == andx64) {
       c_code += "BPF_ATOMIC_OP(64, BPF_AND, " + get_reg_str(node_v1, id1) +
                 ", " + get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* orx16 dst src off */
    else if (node_v == orx16) {
       c_code += "BPF_ATOMIC_OP(16, BPF_OR, " + get_reg_str(node_v1, id1) +
                 ", " + get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3))  + "),\n";
    }

    /* orx32 dst src off */
    else if (node_v == orx32) {
       c_code += "BPF_ATOMIC_OP(32, BPF_OR, " + get_reg_str(node_v1, id1) +
                 ", " + get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3))  + "),\n";
    }

    /* orx64 dst src off */
    else if (node_v == orx64) {
       c_code += "BPF_ATOMIC_OP(64, BPF_OR, " + get_reg_str(node_v1, id1) +
                 ", " + get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3))  + "),\n";
    }

    /* xorx16 dst src off */
    else if (node_v == xorx16) {
       c_code += "BPF_ATOMIC_OP(16, BPF_XOR, " + get_reg_str(node_v1, id1) +
                 ", " + get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3))  + "),\n";
    }

    /* xorx32 dst src off */
    else if (node_v == xorx32) {
       c_code += "BPF_ATOMIC_OP(32, BPF_XOR, " + get_reg_str(node_v1, id1) +
                 ", " + get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* xorx64 dst src off */
    else if (node_v == xorx64) {
       c_code += "BPF_ATOMIC_OP(64, BPF_XOR, " + get_reg_str(node_v1, id1) +
                 ", " + get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* addfx16 dst src off */
    else if (node_v == addfx16) {
       c_code += "BPF_ATOMIC_OP(16, BPF_ADD | BPF_FETCH, " +
                 get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* addfx32 dst src off */
    else if (node_v == addfx32) {
       c_code += "BPF_ATOMIC_OP(32, BPF_ADD | BPF_FETCH, " +
                 get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* addfx64 dst src off */
    else if (node_v == addfx64) {
       c_code += "BPF_ATOMIC_OP(64, BPF_ADD | BPF_FETCH, " +
                 get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* andfx16 dst src off */
    else if (node_v == andfx16) {
       c_code += "BPF_ATOMIC_OP(16, BPF_AND | BPF_FETCH, " +
                 get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* andfx32 dst src off */
    else if (node_v == andfx32) {
       c_code += "BPF_ATOMIC_OP(32, BPF_AND | BPF_FETCH, " +
                 get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* andfx64 dst src off */
    else if (node_v == andfx64) {
       c_code += "BPF_ATOMIC_OP(64, BPF_AND | BPF_FETCH, " +
                  get_reg_str(node_v1, id1) + ", " +
                  get_reg_str(node_v2, id2) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* orfx16 dst src off */
    else if (node_v == orfx16) {
       c_code += "BPF_ATOMIC_OP(16, BPF_OR | BPF_FETCH, " +
                 get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* orfx32 dst src off */
    else if (node_v == orfx32) {
       c_code += "BPF_ATOMIC_OP(32, BPF_OR | BPF_FETCH, " +
                 get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* orfx64 dst src off */
    else if (node_v == orfx64) {
       c_code += "BPF_ATOMIC_OP(64, BPF_OR | BPF_FETCH, " +
                 get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* xorfx16 dst src off */
    else if (node_v == xorfx16) {
       c_code += "BPF_ATOMIC_OP(16, BPF_XOR | BPF_FETCH, " +
                 get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* xorfx32 dst src off */
    else if (node_v == xorfx32) {
       c_code += "BPF_ATOMIC_OP(32, BPF_XOR | BPF_FETCH, " +
                 get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* xorfx64 dst src off */
    else if (node_v == xorfx64) {
       c_code += "BPF_ATOMIC_OP(64, BPF_XOR | BPF_FETCH, " +
                 get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* xchgx16 dst src off */
    else if (node_v == xchgx16) {
       c_code += "BPF_ATOMIC_OP(16, BPF_XCHG, " +
                 get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* xchgx32 dst src off */
    else if (node_v == xchgx32) {
       c_code += "BPF_ATOMIC_OP(32, BPF_XCHG, " +
                 get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* xchgx64 dst src off */
    else if (node_v == xchgx64) {
       c_code += "BPF_ATOMIC_OP(64, BPF_XCHG, " + get_reg_str(node_v1, id1) +
                 ", " + get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* cmpxchgx16 dst src off */
    else if (node_v == cmpxchgx16) {
       c_code += "BPF_ATOMIC_OP(16, BPF_CMPXCHG, " + get_reg_str(node_v1, id1)
                 + ", " + get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* cmpxchgx32 dst src off */
    else if (node_v == cmpxchgx32) {
       c_code += "BPF_ATOMIC_OP(32, BPF_CMPXCHG, " + get_reg_str(node_v1, id1)
                 + ", " + get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* cmpxchgx64 dst src off */
    else if (node_v == cmpxchgx64) {
       c_code += "BPF_ATOMIC_OP(64, BPF_CMPXCHG, " + get_reg_str(node_v1, id1)
                 + ", " + get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* ldmapfd dst imm  */
    else if (node_v == ldmapfd) {
       c_code += "BPF_LD_MAP_FD(" + get_reg_str(node_v1, id1) + ", " +
                std::to_string(get_val<int>(node_v2, id2)) + "),\n";
    }

    /* ld64 dst imm  */
    else if (node_v == ld64) {
       c_code += "BPF_LD_IMM64(" + get_reg_str(node_v1, id1) + ", " +
                std::to_string(get_val<int>(node_v2, id2)) + "),\n";
    }

    /* ldabs8 imm  */
    else if (node_v == ldabs8) {
       c_code += "BPF_LD_ABS(8, " + std::to_string(get_val<int>(node_v1, id1))
                 + "),\n";
    }

    /* ldabs16 imm  */
    else if (node_v == ldabs16) {
       c_code += "BPF_LD_ABS(16, " + std::to_string(get_val<int>(node_v1, id1))
                 + "),\n";
    }

    /* ldabs32 imm  */
    else if (node_v == ldabs32) {
       c_code += "BPF_LD_ABS(32, " + std::to_string(get_val<int>(node_v1, id1))
                 + "),\n";
    }

    /* ldabs64 imm  */
    else if (node_v == ldabs64) {
       c_code += "BPF_LD_ABS(64, " + std::to_string(get_val<int>(node_v1, id1))
                 + "),\n";
    }

    /* ldind8 src imm  */
    else if (node_v == ldind8) {
       c_code += "BPF_LD_IND(8, " + get_reg_str(node_v1, id1) + ", " +
                 std::to_string(get_val<int>(node_v2, id2)) + "),\n";
    }

    /* ldind16 src imm  */
    else if (node_v == ldind16) {
       c_code += "BPF_LD_IND(16, " + get_reg_str(node_v1, id1) + ", " +
                 std::to_string(get_val<int>(node_v2, id2)) + "),\n";
    }

    /* ldind32 src imm  */
    else if (node_v == ldind32) {
       c_code += "BPF_LD_IND(32, " + get_reg_str(node_v1, id1) + ", " +
                 std::to_string(get_val<int>(node_v2, id2)) + "),\n";
    }

    /* ldind64 src imm  */
    else if (node_v == ldind64) {
       c_code += "BPF_LD_IND(64, " + get_reg_str(node_v1, id1) + ", " +
                 std::to_string(get_val<int>(node_v2, id2)) + "),\n";
    }

    /* ldx8 dst src off  */
    else if (node_v == ldx8) {
       c_code += "BPF_LDX_MEM(8, " + get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* ldx16 dst src off  */
    else if (node_v == ldx16) {
       c_code += "BPF_LDX_MEM(16, " + get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* ldx32 dst src off  */
    else if (node_v == ldx32) {
       c_code += "BPF_LDX_MEM(32, " + get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* ldx64 dst src off  */
    else if (node_v == ldx64) {
       c_code += "BPF_LDX_MEM(64, " + get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* st8 dst off imm  */
    else if (node_v == st8) {
       c_code += "BPF_ST_MEM(8, " + get_reg_str(node_v1, id1) + ", " +
                 std::to_string((__s16)get_val<int>(node_v2, id2)) + ", " +
                 std::to_string(get_val<int>(node_v3, id3)) + "),\n";
    }

    /* st16 dst off imm   */
    else if (node_v == st16) {
       c_code += "BPF_ST_MEM(16, " + get_reg_str(node_v1, id1) + ", " +
                 std::to_string((__s16)get_val<int>(node_v2, id2)) + ", " +
                 std::to_string(get_val<int>(node_v3, id3)) + "),\n";
    }

    /* st32 dst off imm   */
    else if (node_v == st32) {
       c_code += "BPF_ST_MEM(32, " + get_reg_str(node_v1, id1) + ", " +
                 std::to_string((__s16)get_val<int>(node_v2, id2)) + ", " +
                 std::to_string(get_val<int>(node_v3, id3)) + "),\n";
    }

    /* st64 dst off imm   */
    else if (node_v == st64) {
       c_code += "BPF_ST_MEM(64, " + get_reg_str(node_v1, id1) + ", " +
                 std::to_string((__s16)get_val<int>(node_v2, id2)) + ", " +
                 std::to_string(get_val<int>(node_v3, id3)) + "),\n";
    }

    /* stx8 dst src off  */
    else if (node_v == stx8) {
       c_code += "BPF_STX_MEM(8, " + get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* stx16 dst src off  */
    else if (node_v == stx16) {
       c_code += "BPF_STX_MEM(16, " + get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* stx32 dst src off  */
    else if (node_v == stx32) {
       c_code += "BPF_STX_MEM(32, " + get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* stx64 dst src off  */
    else if (node_v == stx64) {
       c_code += "BPF_STX_MEM(64, " + get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* stxx8 dst src off  */
    else if (node_v == stxx8) {
       c_code += "BPF_STX_XADD(8, " + get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* stxx16 dst src off  */
    else if (node_v == stxx16) {
       c_code += "BPF_STX_XADD(16, " + get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* stxx32 dst src off  */
    else if (node_v == stxx32) {
       c_code += "BPF_STX_XADD(32, " + get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* stxx64 dst src off  */
    else if (node_v == stxx64) {
       c_code += "BPF_STX_XADD(64, " + get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* ja off */
    else if (node_v == ja) {
       c_code += "BPF_JMP_A(" +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* jeq dst src|imm off */
    else if (node_v == jeq) {
      if (node_v2 == imm_int)
        c_code += "BPF_JMP_IMM(BPF_JEQ, " + get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP_REG(BPF_JEQ, " + get_reg_str(node_v1, id1) + ", " +
                   get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* jgt dst src|imm off */
    else if (node_v == jgt) {
      if (node_v2 == imm_int)
        c_code += "BPF_JMP_IMM(BPF_JGT, " + get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP_REG(BPF_JGT, " + get_reg_str(node_v1, id1) + ", " +
                   get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* jge dst src|imm off */
    else if (node_v == jge) {
      if (node_v2 == imm_int)
        c_code += "BPF_JMP_IMM(BPF_JGE, " + get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP_REG(BPF_JGE, " + get_reg_str(node_v1, id1) + ", " +
                   get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* jlt dst src|imm off */
    else if (node_v == jlt) {
      if (node_v2 == imm_int)
        c_code += "BPF_JMP_IMM(BPF_JLT, " + get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP_REG(BPF_JLT, " + get_reg_str(node_v1, id1) + ", " +
                   get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* jle dst src|imm off */
    else if (node_v == jle) {
      if (node_v2 == imm_int)
        c_code += "BPF_JMP_IMM(BPF_JLE, " + get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP_REG(BPF_JLE, " + get_reg_str(node_v1, id1) + ", " +
                   get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* jset dst src|imm off */
    else if (node_v == jset) {
      if (node_v2 == imm_int)
        c_code += "BPF_JMP_IMM(BPF_JSET, " + get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP_REG(BPF_JSET, " + get_reg_str(node_v1, id1) + ", " +
                   get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* jne dst src|imm off */
    else if (node_v == jne) {
      if (node_v2 == imm_int)
        c_code += "BPF_JMP_IMM(BPF_JNE, " + get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP_REG(BPF_JNE, " + get_reg_str(node_v1, id1) + ", " +
                   get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* jsgt dst src|imm off */
    else if (node_v == jsgt) {
      if (node_v2 == imm_int)
        c_code += "BPF_JMP_IMM(BPF_JSGT, " + get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP_REG(BPF_JSGT, " + get_reg_str(node_v1, id1) + ", " +
                   get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* jsge dst src|imm off */
    else if (node_v == jsge) {
      if (node_v2 == imm_int)
        c_code += "BPF_JMP_IMM(BPF_JSGE, " + get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP_REG(BPF_JSGE, " + get_reg_str(node_v1, id1) + ", " +
                   get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* jslt dst src|imm off */
    else if (node_v == jslt) {
      if (node_v2 == imm_int)
        c_code += "BPF_JMP_IMM(BPF_JSLT, " + get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP_REG(BPF_JSLT, " + get_reg_str(node_v1, id1) + ", " +
                   get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* jsle dst src|imm off */
    else if (node_v == jsle) {
      if (node_v2 == imm_int)
        c_code += "BPF_JMP_IMM(BPF_JSLE, " + get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP_REG(BPF_JSLE, " + get_reg_str(node_v1, id1) + ", " +
                   get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* call imm */
    else if (node_v == call) {
      error("error: call: instruction not yet supported.");
    }

    /* rel imm */
    else if (node_v == rel) {
      c_code += "BPF_CALL_REL(" + std::to_string(get_val<int>(node_v1, id1)) +
                "),\n";
    }

    /* exit */
    else if (node_v == exit_ins) {
      c_code += "BPF_EXIT_INSN(),\n";
    }

    /* jeq32 dst src|imm off */
    else if (node_v == jeq32) {
      if (node_v2 == imm_int)
        c_code += "BPF_JMP32_IMM(BPF_JEQ, " + get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP32_REG(BPF_JEQ, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* jgt32 dst src|imm off */
    else if (node_v == jgt32) {
      if (node_v2 == imm_int)
        c_code += "BPF_JMP32_IMM(BPF_JGT, " + get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP32_REG(BPF_JGT, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* jge32 dst src|imm off */
    else if (node_v == jge32) {
      if (node_v2 == imm_int)
        c_code += "BPF_JMP32_IMM(BPF_JGE, " + get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP32_REG(BPF_JGE, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* jlt32 dst src|imm off */
    else if (node_v == jlt32) {
      if (node_v2 == imm_int)
        c_code += "BPF_JMP32_IMM(BPF_JLT, " + get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP32_REG(BPF_JLT, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* jle32 dst src|imm off */
    else if (node_v == jle32) {
      if (node_v2 == imm_int)
        c_code += "BPF_JMP32_IMM(BPF_JLE, " + get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP32_REG(BPF_JLE, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* jset32 dst src|imm off */
    else if (node_v == jset32) {
      if (node_v2 == imm_int)
        c_code += "BPF_JMP32_IMM(BPF_JSET, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP32_REG(BPF_JSET, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* jne32 dst src|imm off */
    else if (node_v == jne32) {
      if (node_v2 == imm_int)
        c_code += "BPF_JMP32_IMM(BPF_JNE, " + get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP32_REG(BPF_JNE, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* jsgt32 dst src|imm off */
    else if (node_v == jsgt32) {
      if (node_v2 == imm_int)
        c_code += "BPF_JMP32_IMM(BPF_JSGT, " + get_reg_str(node_v1, id1) + ", "
                   + std::to_string(get_val<int>(node_v2, id2)) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP32_REG(BPF_JSGT, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* jsge32 dst src|imm off */
    else if (node_v == jsge32) {
      if (node_v2 == imm_int)
        c_code += "BPF_JMP32_IMM(BPF_JSGE, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP32_REG(BPF_JSGE, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* jslt32 dst src|imm off */
    else if (node_v == jslt32) {
      if (node_v2 == imm_int)
        c_code += "BPF_JMP32_IMM(BPF_JSLT, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP32_REG(BPF_JSLT, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* jsle32 dst src|imm off */
    else if (node_v == jsle32) {
      if (node_v2 == imm_int)
        c_code += "BPF_JMP32_IMM(BPF_JSLE, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP32_REG(BPF_JSLE, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    }

    /* zext dst */
    else if (node_v == zext) {
      c_code += "BPF_ZEXT_REG(" + get_reg_str(node_v1, id1) + "),\n";
    }

  }

  c_code += TAIL_CSTRUCT;

  std::ofstream ofs;
  ofs.open(out_fname);
  if (!ofs.is_open())
    error("error: std::ofstream::open() failed opening file: ", out_fname);
  ofs<<c_code;
  ofs.close();
}
