#include <../headers/bpf_insn.h>
#include "codegen.hpp"

static inline uint max_insns() {
  uint max_insns = 0;
  for (ast_t node : ast) {
    if (node.type == instr)
      max_insns++;
    if (node.node_v == ld64 || node.node_v == ldmapfd)
      max_insns++;
  }
  return max_insns;
}

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
  else error("map_reg(): unknown register: ", id);
  return -1;
}

template <typename T>
static inline T get_val(Node n, ident_t id) {
  if      (n == imm_int)   return stoi_w(id);
  else if (n == imm_float) return stof_w(id);
  else error("get_val(): not an immediate: ", pp_node(n), ", id: ", id);
  return -1;
}

static inline __u8 get_reg(Node n, ident_t id) {
  if (n == regs) return map_reg(id);
  else error("get_reg(): not a register: ", pp_node(n), ", id: ", id);
  return -1;
}

static inline std::string get_reg_str(Node n, ident_t id) {
  if (n != regs)
    error("get_reg_str(): not a register: ", pp_node(n), ", id: ", id);

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

  error("get_reg_str(): not a register: ", pp_node(n), ", id: ", id);
  return "";
}

void codegen(std::string out_fname) {
  uint    size;
  ast_t   node;
  Node    node_v, node_v1, node_v2, node_v3;
  ident_t id1, id2, id3;
  uint    i, prog_len, ops;
  // errors reported by valgrind are subdued when assigning a smaller
  // ``prog`` array size.
  struct bpf_insn prog[1000000];

  size     = ast.size();
  prog_len = 0;

  // suppress -Werror=maybe-uninitialized warnings.
  node_v1 = node_v2 = node_v3 = dead_ins;

  for (i=0; i<size; i++) {
    node   = ast[i];
    node_v = node.node_v;
    ops    = node.arg_num;

    if (ops == 1) {
      id1     = ast[i+1].id;
      node_v1 = ast[i+1].node_v;
    }
    else if (ops == 2) {
      id1     = ast[i+1].id;
      id2     = ast[i+2].id;
      node_v1 = ast[i+1].node_v;
      node_v2 = ast[i+2].node_v;
    }
    else if (ops == 3) {
      id1     = ast[i+1].id;
      id2     = ast[i+2].id;
      id3     = ast[i+3].id;
      node_v1 = ast[i+1].node_v;
      node_v2 = ast[i+2].node_v;
      node_v3 = ast[i+3].node_v;
    }

    switch (node_v) {
    /* ALU instructions: */
    /* 64-bit: */
    /* add dst src|imm */
    case add:
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU64_IMM(BPF_ADD,
                                         get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU64_REG(BPF_ADD,
                                          get_reg(node_v1, id1),
                                          get_reg(node_v2, id2));
    break;

    /* sub dst src|imm */
    case sub:
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU64_IMM(BPF_SUB,
                                         get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU64_REG(BPF_SUB,
                                          get_reg(node_v1, id1),
                                          get_reg(node_v2, id2));
    break;

    /* mul dst src|imm */
    case mul:
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU64_IMM(BPF_MUL,
                                         get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU64_REG(BPF_MUL,
                                          get_reg(node_v1, id1),
                                          get_reg(node_v2, id2));
    break;

    /* div dst src|imm */
    case div_ins:
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU64_IMM(BPF_DIV,
                                         get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU64_REG(BPF_DIV,
                                          get_reg(node_v1, id1),
                                          get_reg(node_v2, id2));
    break;

    /* or dst src|imm */
    case or_ins:
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU64_IMM(BPF_OR,
                                         get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU64_REG(BPF_OR,
                                          get_reg(node_v1, id1),
                                          get_reg(node_v2, id2));
    break;

    /* and dst src|imm */
    case and_ins:
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU64_IMM(BPF_AND,
                                         get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU64_REG(BPF_AND,
                                          get_reg(node_v1, id1),
                                          get_reg(node_v2, id2));
    break;

    /* lsh dst src|imm */
    case lsh:
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU64_IMM(BPF_LSH,
                                         get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU64_REG(BPF_LSH,
                                          get_reg(node_v1, id1),
                                          get_reg(node_v2, id2));
    break;

    /* rsh dst src|imm */
    case rsh:
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU64_IMM(BPF_RSH,
                                         get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU64_REG(BPF_RSH,
                                          get_reg(node_v1, id1),
                                          get_reg(node_v2, id2));
    break;

    /* neg dst */
    case neg:
        prog[prog_len++] = BPF_ALU64_IMM(BPF_NEG, get_reg(node_v1, id1), 0);
    break;

    /* mod dst src|imm */
    case mod:
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU64_IMM(BPF_MOD,
                                         get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU64_REG(BPF_MOD,
                                          get_reg(node_v1, id1),
                                          get_reg(node_v2, id2));
    break;

    /* xor dst src|imm */
    case xor_ins:
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU64_IMM(BPF_XOR,
                                         get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU64_REG(BPF_XOR,
                                          get_reg(node_v1, id1),
                                          get_reg(node_v2, id2));
    break;

    /* mov dst src|imm */
    case mov:
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU64_IMM(BPF_MOV,
                                         get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU64_REG(BPF_MOV,
                                          get_reg(node_v1, id1),
                                          get_reg(node_v2, id2));
    break;

    /* arsh dst src|imm */
    case arsh:
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU64_IMM(BPF_ARSH,
                                         get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU64_REG(BPF_ARSH,
                                          get_reg(node_v1, id1),
                                          get_reg(node_v2, id2));
    break;

    /* 32-bit: */
    /* add32 dst src|imm */
    case add32:
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU32_IMM(BPF_ADD,
                                         get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU32_REG(BPF_ADD,
                                          get_reg(node_v1, id1),
                                          get_reg(node_v2, id2));
    break;

    /* sub32 dst src|imm */
    case sub32:
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU32_IMM(BPF_SUB,
                                         get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU32_REG(BPF_SUB,
                                          get_reg(node_v1, id1),
                                          get_reg(node_v2, id2));
    break;

    /* mul32 dst src|imm */
    case mul32:
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU32_IMM(BPF_MUL,
                                         get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU32_REG(BPF_MUL,
                                          get_reg(node_v1, id1),
                                          get_reg(node_v2, id2));
    break;

    /* div32 dst src|imm */
    case div32:
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU32_IMM(BPF_DIV,
                                         get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU32_REG(BPF_DIV,
                                          get_reg(node_v1, id1),
                                          get_reg(node_v2, id2));
    break;

    /* or32 dst src|imm */
    case or32:
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU32_IMM(BPF_OR,
                                         get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU32_REG(BPF_OR,
                                          get_reg(node_v1, id1),
                                          get_reg(node_v2, id2));
    break;

    /* and32 dst src|imm */
    case and32:
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU32_IMM(BPF_AND,
                                         get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU32_REG(BPF_AND,
                                          get_reg(node_v1, id1),
                                          get_reg(node_v2, id2));
    break;

    /* lsh32 dst src|imm */
    case lsh32:
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU32_IMM(BPF_LSH,
                                         get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU32_REG(BPF_LSH,
                                          get_reg(node_v1, id1),
                                          get_reg(node_v2, id2));
    break;

    /* rsh32 dst src|imm */
    case rsh32:
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU32_IMM(BPF_RSH,
                                         get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU32_REG(BPF_RSH,
                                          get_reg(node_v1, id1),
                                          get_reg(node_v2, id2));
    break;

    /* neg32 dst */
    case neg32:
        prog[prog_len++] = BPF_ALU32_IMM(BPF_NEG, get_reg(node_v1, id1), 0);
    break;

    /* mod32 dst src|imm */
    case mod32:
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU32_IMM(BPF_MOD,
                                         get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU32_REG(BPF_MOD,
                                          get_reg(node_v1, id1),
                                          get_reg(node_v2, id2));
    break;

    /* xor32 dst src|imm */
    case xor32:
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU32_IMM(BPF_XOR,
                                         get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU32_REG(BPF_XOR,
                                          get_reg(node_v1, id1),
                                          get_reg(node_v2, id2));
    break;

    /* mov32 dst src|imm */
    case mov32:
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU32_IMM(BPF_MOV,
                                         get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU32_REG(BPF_MOV,
                                          get_reg(node_v1, id1),
                                          get_reg(node_v2, id2));
    break;

    /* arsh32 dst src|imm */
    case arsh32:
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_ALU32_IMM(BPF_ARSH,
                                         get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
         prog[prog_len++] = BPF_ALU32_REG(BPF_ARSH,
                                          get_reg(node_v1, id1),
                                          get_reg(node_v2, id2));
    break;

    /* mov32 dst src|imm */
    /*
    case mov32:
      if (node_v2 == imm_int)
        prog[prog_len++] = BPF_MOV32_IMM(get_reg(node_v1, id1),
                                         get_val<int>(node_v2, id2));
      else
        prog[prog_len++] = BPF_MOV32_REG(get_reg(node_v1, id1),
                                         get_reg(node_v2, id2));
    break;
    */

    /* Endianess conversion (Byteswap) instructions: */
    /* le16 dst */
    case le16:
      prog[prog_len++] = BPF_ENDIAN(BPF_TO_LE, get_reg(node_v1, id1), 16);
    break;

    /* le32 dst */
    case le32:
      prog[prog_len++] = BPF_ENDIAN(BPF_TO_LE, get_reg(node_v1, id1), 32);
    break;

    /* le64 dst */
    case le64:
      prog[prog_len++] = BPF_ENDIAN(BPF_TO_LE, get_reg(node_v1, id1), 64);
    break;

    /* be16 dst */
    case be16:
      prog[prog_len++] = BPF_ENDIAN(BPF_TO_BE, get_reg(node_v1, id1), 16);
    break;

    /* be32 dst */
    case be32:
      prog[prog_len++] = BPF_ENDIAN(BPF_TO_BE, get_reg(node_v1, id1), 32);
    break;

    /* be64 dst */
    case be64:
      prog[prog_len++] = BPF_ENDIAN(BPF_TO_BE, get_reg(node_v1, id1), 64);
    break;

    /* Atomic operations: */
    /* addx16 dst src off */
    case addx16:
      prog[prog_len++] = BPF_ATOMIC_OP(16, BPF_ADD,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    break;

    /* addx32 dst src off */
    case addx32:
      prog[prog_len++] = BPF_ATOMIC_OP(32, BPF_ADD,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    break;

    /* addx64 dst src off */
    case addx64:
      prog[prog_len++] = BPF_ATOMIC_OP(64, BPF_ADD,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    break;

    /* andx16 dst src off */
    case andx16:
      prog[prog_len++] = BPF_ATOMIC_OP(16, BPF_AND,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    break;

    /* andx32 dst src off */
    case andx32:
      prog[prog_len++] = BPF_ATOMIC_OP(32, BPF_AND,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    break;

    /* andx64 dst src off */
    case andx64:
      prog[prog_len++] = BPF_ATOMIC_OP(64, BPF_AND,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    break;

    /* orx16 dst src off */
    case orx16:
      prog[prog_len++] = BPF_ATOMIC_OP(16, BPF_OR,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    break;

    /* orx32 dst src off */
    case orx32:
      prog[prog_len++] = BPF_ATOMIC_OP(32, BPF_OR,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    break;

    /* orx64 dst src off */
    case orx64:
      prog[prog_len++] = BPF_ATOMIC_OP(64, BPF_OR,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    break;

    /* xorx16 dst src off */
    case xorx16:
      prog[prog_len++] = BPF_ATOMIC_OP(16, BPF_XOR,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    break;

    /* xorx32 dst src off */
    case xorx32:
      prog[prog_len++] = BPF_ATOMIC_OP(32, BPF_XOR,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    break;

    /* xorx64 dst src off */
    case xorx64:
      prog[prog_len++] = BPF_ATOMIC_OP(64, BPF_XOR,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    break;

    /* addfx16 dst src off */
    case addfx16:
      prog[prog_len++] = BPF_ATOMIC_OP(16, BPF_ADD | BPF_FETCH,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    break;

    /* addfx32 dst src off */
    case addfx32:
      prog[prog_len++] = BPF_ATOMIC_OP(32, BPF_ADD | BPF_FETCH,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    break;

    /* addfx64 dst src off */
    case addfx64:
      prog[prog_len++] = BPF_ATOMIC_OP(64, BPF_ADD | BPF_FETCH,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    break;

    /* andfx16 dst src off */
    case andfx16:
      prog[prog_len++] = BPF_ATOMIC_OP(16, BPF_AND | BPF_FETCH,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    break;

    /* andfx32 dst src off */
    case andfx32:
      prog[prog_len++] = BPF_ATOMIC_OP(32, BPF_AND | BPF_FETCH,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    break;

    /* andfx64 dst src off */
    case andfx64:
      prog[prog_len++] = BPF_ATOMIC_OP(64, BPF_AND | BPF_FETCH,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    break;

    /* orfx16 dst src off */
    case orfx16:
      prog[prog_len++] = BPF_ATOMIC_OP(16, BPF_OR | BPF_FETCH,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    break;

    /* orfx32 dst src off */
    case orfx32:
      prog[prog_len++] = BPF_ATOMIC_OP(32, BPF_OR | BPF_FETCH,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    break;

    /* orfx64 dst src off */
    case orfx64:
      prog[prog_len++] = BPF_ATOMIC_OP(64, BPF_OR | BPF_FETCH,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    break;

    /* xorfx16 dst src off */
    case xorfx16:
      prog[prog_len++] = BPF_ATOMIC_OP(16, BPF_XOR | BPF_FETCH,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    break;

    /* xorfx32 dst src off */
    case xorfx32:
      prog[prog_len++] = BPF_ATOMIC_OP(32, BPF_XOR | BPF_FETCH,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    break;

    /* xorfx64 dst src off */
    case xorfx64:
      prog[prog_len++] = BPF_ATOMIC_OP(64, BPF_XOR | BPF_FETCH,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    break;

    /* xchgx16 dst src off */
    case xchgx16:
      prog[prog_len++] = BPF_ATOMIC_OP(16, BPF_XCHG,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    break;

    /* xchgx32 dst src off */
    case xchgx32:
      prog[prog_len++] = BPF_ATOMIC_OP(32, BPF_XCHG,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    break;

    /* xchgx64 dst src off */
    case xchgx64:
      prog[prog_len++] = BPF_ATOMIC_OP(64, BPF_XCHG,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    break;

    /* cmpxchgx16 dst src off */
    case cmpxchgx16:
      prog[prog_len++] = BPF_ATOMIC_OP(16, BPF_CMPXCHG,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    break;

    /* cmpxchgx32 dst src off */
    case cmpxchgx32:
      prog[prog_len++] = BPF_ATOMIC_OP(32, BPF_CMPXCHG,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    break;

    /* cmpxchgx64 dst src off */
    case cmpxchgx64:
      prog[prog_len++] = BPF_ATOMIC_OP(64, BPF_CMPXCHG,
                                       get_reg(node_v1, id1),
                                       get_reg(node_v2, id2),
                                       (__s16)get_val<int>(node_v3, id3));
    break;

    /* ldmapfd dst imm */
    case ldmapfd:
      prog[prog_len++] = BPF_LD_IMM64_RAW_1(get_reg(node_v1, id1),
                                            BPF_PSEUDO_MAP_FD,
                                            get_val<int>(node_v2, id2));
      prog[prog_len++] = BPF_LD_IMM64_RAW_2(get_reg(node_v1, id1),
                                            BPF_PSEUDO_MAP_FD,
                                            get_val<int>(node_v2, id2));
    break;

    /* ld64 dst imm */
    case ld64:
      prog[prog_len++] = BPF_LD_IMM64_RAW_1(get_reg(node_v1, id1),
                                            0,
                                            get_val<int>(node_v2, id2));
      prog[prog_len++] = BPF_LD_IMM64_RAW_2(get_reg(node_v1, id1),
                                            0,
                                            get_val<int>(node_v2, id2));
    break;

    /* ldabs8 imm */
    case ldabs8:
      prog[prog_len++] = BPF_LD_ABS(8, get_val<int>(node_v1, id1));
    break;

    /* ldabs16 imm */
    case ldabs16:
      prog[prog_len++] = BPF_LD_ABS(16, get_val<int>(node_v1, id1));
    break;

    /* ldabs32 imm */
    case ldabs32:
      prog[prog_len++] = BPF_LD_ABS(32, get_val<int>(node_v1, id1));
    break;

    /* ldabs64 imm */
    case ldabs64:
      prog[prog_len++] = BPF_LD_ABS(64, get_val<int>(node_v1, id1));
    break;

    /* ldind8 src imm */
    case ldind8:
      prog[prog_len++] =
        BPF_LD_IND(8, get_reg(node_v1, id1), get_val<int>(node_v2, id2));
    break;

    /* ldind16 src imm */
    case ldind16:
      prog[prog_len++] =
        BPF_LD_IND(16, get_reg(node_v1, id1), get_val<int>(node_v2, id2));
    break;

    /* ldind32 src imm */
    case ldind32:
      prog[prog_len++] =
        BPF_LD_IND(32, get_reg(node_v1, id1), get_val<int>(node_v2, id2));
    break;

    /* ldind64 src imm */
    case ldind64:
      prog[prog_len++] =
        BPF_LD_IND(64, get_reg(node_v1, id1), get_val<int>(node_v2, id2));
    break;

    /* ldx8 dst src off */
    case ldx8:
      prog[prog_len++] =
        BPF_LDX_MEM(8,
                    get_reg(node_v1, id1),
                    get_reg(node_v2, id2),
                    (__s16)get_val<int>(node_v3, id3));
    break;

    /* ldx16 dst src off */
    case ldx16:
      prog[prog_len++] =
        BPF_LDX_MEM(16,
                    get_reg(node_v1, id1),
                    get_reg(node_v2, id2),
                    (__s16)get_val<int>(node_v3, id3));
    break;

    /* ldx32 dst src off */
    case ldx32:
      prog[prog_len++] =
        BPF_LDX_MEM(32,
                    get_reg(node_v1, id1),
                    get_reg(node_v2, id2),
                    (__s16)get_val<int>(node_v3, id3));
    break;

    /* ldx64 dst src off */
    case ldx64:
      prog[prog_len++] =
        BPF_LDX_MEM(64,
                    get_reg(node_v1, id1),
                    get_reg(node_v2, id2),
                    (__s16)get_val<int>(node_v3, id3));
    break;

    /* st8 dst off imm */
    case st8:
      prog[prog_len++] =
        BPF_ST_MEM(8,
                   get_reg(node_v1, id1),
                   (__s16)get_val<int>(node_v2, id2),
                   get_val<int>(node_v3, id3));
    break;

    /* st16 dst off imm */
    case st16:
      prog[prog_len++] =
        BPF_ST_MEM(16,
                   get_reg(node_v1, id1),
                   (__s16)get_val<int>(node_v2, id2),
                   get_val<int>(node_v3, id3));
    break;

    /* st32 dst off imm */
    case st32:
      prog[prog_len++] =
        BPF_ST_MEM(32,
                   get_reg(node_v1, id1),
                   (__s16)get_val<int>(node_v2, id2),
                   get_val<int>(node_v3, id3));
    break;

    /* st64 dst off imm */
    case st64:
      prog[prog_len++] =
        BPF_ST_MEM(64,
                   get_reg(node_v1, id1),
                   (__s16)get_val<int>(node_v2, id2),
                   get_val<int>(node_v3, id3));
    break;

    /* stx8 dst src off */
    case stx8:
      prog[prog_len++] =
        BPF_STX_MEM(8,
                    get_reg(node_v1, id1),
                    get_reg(node_v2, id2),
                    (__s16)get_val<int>(node_v3, id3));
    break;

    /* stx16 dst src off */
    case stx16:
      prog[prog_len++] =
        BPF_STX_MEM(16,
                    get_reg(node_v1, id1),
                    get_reg(node_v2, id2),
                    (__s16)get_val<int>(node_v3, id3));
    break;

    /* stx32 dst src off */
    case stx32:
      prog[prog_len++] =
        BPF_STX_MEM(32,
                    get_reg(node_v1, id1),
                    get_reg(node_v2, id2),
                    (__s16)get_val<int>(node_v3, id3));
    break;

    /* stx64 dst src off */
    case stx64:
      prog[prog_len++] =
        BPF_STX_MEM(64,
                    get_reg(node_v1, id1),
                    get_reg(node_v2, id2),
                    (__s16)get_val<int>(node_v3, id3));
    break;

    /* stxx8 dst src off */
    case stxx8:
      prog[prog_len++] =
        BPF_STX_XADD(8,
                     get_reg(node_v1, id1),
                     get_reg(node_v2, id2),
                     (__s16)get_val<int>(node_v3, id3));
    break;

    /* stxx16 dst src off */
    case stxx16:
      prog[prog_len++] =
        BPF_STX_XADD(16,
                     get_reg(node_v1, id1),
                     get_reg(node_v2, id2),
                     (__s16)get_val<int>(node_v3, id3));
    break;

    /* stxx32 dst src off */
    case stxx32:
      prog[prog_len++] =
        BPF_STX_XADD(32,
                     get_reg(node_v1, id1),
                     get_reg(node_v2, id2),
                     (__s16)get_val<int>(node_v3, id3));
    break;

    /* stxx64 dst src off */
    case stxx64:
      prog[prog_len++] =
        BPF_STX_XADD(64,
                     get_reg(node_v1, id1),
                     get_reg(node_v2, id2),
                     (__s16)get_val<int>(node_v3, id3));
    break;

    /* Branch instructions: */
    /* 64-bit: */

    /* ja off */
    case ja:
      prog[prog_len++] = BPF_JMP_A((__s16)get_val<int>(node_v1, id1));
    break;

    /* jeq dst src|imm off */
    case jeq:
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP_IMM(BPF_JEQ,
                       get_reg(node_v1, id1),
                       get_val<int>(node_v2, id2),
                       (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP_REG(BPF_JEQ,
                      get_reg(node_v1, id1),
                      get_reg(node_v2, id2),
                      (__s16)get_val<int>(node_v3, id3));
    break;

    /* jgt dst src|imm off */
    case jgt:
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP_IMM(BPF_JGT,
                       get_reg(node_v1, id1),
                       get_val<int>(node_v2, id2),
                       (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP_REG(BPF_JGT,
                      get_reg(node_v1, id1),
                      get_reg(node_v2, id2),
                      (__s16)get_val<int>(node_v3, id3));
    break;

    /* jge dst src|imm off */
    case jge:
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP_IMM(BPF_JGE,
                       get_reg(node_v1, id1),
                       get_val<int>(node_v2, id2),
                       (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP_REG(BPF_JGE,
                      get_reg(node_v1, id1),
                      get_reg(node_v2, id2),
                      (__s16)get_val<int>(node_v3, id3));
    break;

    /* jlt dst src|imm off */
    case jlt:
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP_IMM(BPF_JLT,
                       get_reg(node_v1, id1),
                       get_val<int>(node_v2, id2),
                       (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP_REG(BPF_JLT,
                      get_reg(node_v1, id1),
                      get_reg(node_v2, id2),
                      (__s16)get_val<int>(node_v3, id3));
    break;

    /* jle dst src|imm off */
    case jle:
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP_IMM(BPF_JLE,
                       get_reg(node_v1, id1),
                       get_val<int>(node_v2, id2),
                       (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP_REG(BPF_JLE,
                      get_reg(node_v1, id1),
                      get_reg(node_v2, id2),
                      (__s16)get_val<int>(node_v3, id3));
    break;

    /* jset dst src|imm off */
    case jset:
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP_IMM(BPF_JSET,
                       get_reg(node_v1, id1),
                       get_val<int>(node_v2, id2),
                       (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP_REG(BPF_JSET,
                      get_reg(node_v1, id1),
                      get_reg(node_v2, id2),
                      (__s16)get_val<int>(node_v3, id3));
    break;

    /* jne dst src|imm off */
    case jne:
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP_IMM(BPF_JNE,
                       get_reg(node_v1, id1),
                       get_val<int>(node_v2, id2),
                       (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP_REG(BPF_JNE,
                      get_reg(node_v1, id1),
                      get_reg(node_v2, id2),
                      (__s16)get_val<int>(node_v3, id3));
    break;

    /* jsgt dst src|imm off */
    case jsgt:
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP_IMM(BPF_JSGT,
                       get_reg(node_v1, id1),
                       get_val<int>(node_v2, id2),
                       (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP_REG(BPF_JSGT,
                      get_reg(node_v1, id1),
                      get_reg(node_v2, id2),
                      (__s16)get_val<int>(node_v3, id3));
    break;

    /* jsge dst src|imm off */
    case jsge:
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP_IMM(BPF_JSGE,
                       get_reg(node_v1, id1),
                       get_val<int>(node_v2, id2),
                       (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP_REG(BPF_JSGE,
                      get_reg(node_v1, id1),
                      get_reg(node_v2, id2),
                      (__s16)get_val<int>(node_v3, id3));
    break;

    /* jslt dst src|imm off */
    case jslt:
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP_IMM(BPF_JSLT,
                       get_reg(node_v1, id1),
                       get_val<int>(node_v2, id2),
                       (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP_REG(BPF_JSLT,
                      get_reg(node_v1, id1),
                      get_reg(node_v2, id2),
                      (__s16)get_val<int>(node_v3, id3));
    break;

    /* jsle dst src|imm off */
    case jsle:
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP_IMM(BPF_JSLE,
                       get_reg(node_v1, id1),
                       get_val<int>(node_v2, id2),
                       (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP_REG(BPF_JSLE,
                      get_reg(node_v1, id1),
                      get_reg(node_v2, id2),
                      (__s16)get_val<int>(node_v3, id3));
    break;

    /* call imm */
    case call:
      error("error: call: instruction not yet supported.");
    break;

    /* rel imm */
    case rel:
      prog[prog_len++] = BPF_CALL_REL(get_val<int>(node_v1, id1));
    break;

    /* exit */
    case exit_ins:
      prog[prog_len++] = BPF_EXIT_INSN();
    break;

    /* 32-bit: */

    /* jeq32 dst src|imm off */
    case jeq32:
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP32_IMM(BPF_JEQ,
                         get_reg(node_v1, id1),
                         get_val<int>(node_v2, id2),
                         (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP32_REG(BPF_JEQ,
                        get_reg(node_v1, id1),
                        get_reg(node_v2, id2),
                        (__s16)get_val<int>(node_v3, id3));
    break;

    /* jgt32 dst src|imm off */
    case jgt32:
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP32_IMM(BPF_JGT,
                         get_reg(node_v1, id1),
                         get_val<int>(node_v2, id2),
                         (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP32_REG(BPF_JGT,
                        get_reg(node_v1, id1),
                        get_reg(node_v2, id2),
                        (__s16)get_val<int>(node_v3, id3));
    break;

    /* jge32 dst src|imm off */
    case jge32:
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP32_IMM(BPF_JGE,
                         get_reg(node_v1, id1),
                         get_val<int>(node_v2, id2),
                         (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP32_REG(BPF_JGE,
                        get_reg(node_v1, id1),
                        get_reg(node_v2, id2),
                        (__s16)get_val<int>(node_v3, id3));
    break;

    /* jlt32 dst src|imm off */
    case jlt32:
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP32_IMM(BPF_JLT,
                         get_reg(node_v1, id1),
                         get_val<int>(node_v2, id2),
                         (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP32_REG(BPF_JLT,
                        get_reg(node_v1, id1),
                        get_reg(node_v2, id2),
                        (__s16)get_val<int>(node_v3, id3));
    break;

    /* jle32 dst src|imm off */
    case jle32:
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP32_IMM(BPF_JLE,
                         get_reg(node_v1, id1),
                         get_val<int>(node_v2, id2),
                         (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP32_REG(BPF_JLE,
                        get_reg(node_v1, id1),
                        get_reg(node_v2, id2),
                        (__s16)get_val<int>(node_v3, id3));
    break;

    /* jset32 dst src|imm off */
    case jset32:
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP32_IMM(BPF_JSET,
                         get_reg(node_v1, id1),
                         get_val<int>(node_v2, id2),
                         (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP32_REG(BPF_JSET,
                        get_reg(node_v1, id1),
                        get_reg(node_v2, id2),
                        (__s16)get_val<int>(node_v3, id3));
    break;

    /* jne32 dst src|imm off */
    case jne32:
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP32_IMM(BPF_JNE,
                         get_reg(node_v1, id1),
                         get_val<int>(node_v2, id2),
                         (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP32_REG(BPF_JNE,
                        get_reg(node_v1, id1),
                        get_reg(node_v2, id2),
                        (__s16)get_val<int>(node_v3, id3));
    break;

    /* jsgt32 dst src|imm off */
    case jsgt32:
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP32_IMM(BPF_JSGT,
                         get_reg(node_v1, id1),
                         get_val<int>(node_v2, id2),
                         (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP32_REG(BPF_JSGT,
                        get_reg(node_v1, id1),
                        get_reg(node_v2, id2),
                        (__s16)get_val<int>(node_v3, id3));
    break;

    /* jsge32 dst src|imm off */
    case jsge32:
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP32_IMM(BPF_JSGE,
                         get_reg(node_v1, id1),
                         get_val<int>(node_v2, id2),
                         (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP32_REG(BPF_JSGE,
                        get_reg(node_v1, id1),
                        get_reg(node_v2, id2),
                        (__s16)get_val<int>(node_v3, id3));
    break;

    /* jslt32 dst src|imm off */
    case jslt32:
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP32_IMM(BPF_JSLT,
                         get_reg(node_v1, id1),
                         get_val<int>(node_v2, id2),
                         (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP32_REG(BPF_JSLT,
                        get_reg(node_v1, id1),
                        get_reg(node_v2, id2),
                        (__s16)get_val<int>(node_v3, id3));
    break;

    /* jsle32 dst src|imm off */
    case jsle32:
      if (node_v2 == imm_int)
        prog[prog_len++] =
           BPF_JMP32_IMM(BPF_JSLE,
                         get_reg(node_v1, id1),
                         get_val<int>(node_v2, id2),
                         (__s16)get_val<int>(node_v3, id3));
      else
        prog[prog_len++] =
          BPF_JMP32_REG(BPF_JSLE,
                        get_reg(node_v1, id1),
                        get_reg(node_v2, id2),
                        (__s16)get_val<int>(node_v3, id3));
    break;

    /* zext dst */
    case zext:
      prog[prog_len++] = BPF_ZEXT_REG(get_reg(node_v1, id1));
    break;

    case regs: case imm_int:
    break;

    default:
      error("Internal code generation error: uncovered case: ",
            pp_node(node_v));
    }
  }

  int fd = open(out_fname.c_str(),
                O_CREAT | O_WRONLY | O_TRUNC, S_IREAD | S_IWUSR);
  if (fd == -1)
    error("open() failed on `", out_fname.c_str(), "`: ", strerror(errno));
  if(write(fd, prog, prog_len * sizeof(struct bpf_insn)) == -1)
    error("write() failed on `", out_fname.c_str(), "`: ", strerror(errno));
  close(fd);
}

void codegen_str(std::string out_fname, std::string struct_name) {
  uint    size, i, ops;
  ast_t   node;
  Node    node_v, node_v1, node_v2, node_v3;
  ident_t id1, id2, id3;

  std::string c_code;
  std::string struct_size = std::to_string(max_insns());

  if (struct_name.size())
    c_code = "static struct bpf_insn " + struct_name + "[" +
             struct_size + "] = {\n";
  else
    c_code = "static struct bpf_insn prog[" + struct_size + "] = {\n";

  size = ast.size();

  // suppress -Werror=maybe-uninitialized warnings.
  node_v1 = node_v2 = node_v3 = dead_ins;

  for (i=0; i<size; i++) {
    node   = ast[i];
    node_v = node.node_v;
    ops    = node.arg_num;

    if (ops == 1) {
      id1     = ast[i+1].id;
      node_v1 = ast[i+1].node_v;
    }
    else if (ops == 2) {
      id1     = ast[i+1].id;
      id2     = ast[i+2].id;
      node_v1 = ast[i+1].node_v;
      node_v2 = ast[i+2].node_v;
    }
    else if (ops == 3) {
      id1     = ast[i+1].id;
      id2     = ast[i+2].id;
      id3     = ast[i+3].id;
      node_v1 = ast[i+1].node_v;
      node_v2 = ast[i+2].node_v;
      node_v3 = ast[i+3].node_v;
    }

    switch (node_v) {
    /* ALU instructions: */
    /* 64-bit: */
    /* add dst src|imm */
    case add:
      if (node_v2 == imm_int)
        c_code += "BPF_ALU64_IMM(BPF_ADD, " +
                  get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU64_REG(BPF_ADD, " +
                   get_reg_str(node_v1, id1) + ", " +
                   get_reg_str(node_v2, id2) + "),\n";
    break;

    /* sub dst src|imm */
    case sub:
      if (node_v2 == imm_int)
        c_code += "BPF_ALU64_IMM(BPF_SUB, " +
                  get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU64_REG(BPF_SUB, " +
                   get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + "),\n";
    break;

    /* mul dst src|imm */
    case mul:
      if (node_v2 == imm_int)
        c_code += "BPF_ALU64_IMM(BPF_MUL, " +
                  get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU64_REG(BPF_MUL, " +
                   get_reg_str(node_v1, id1) + ", " +
                   get_reg_str(node_v2, id2) + "),\n";
    break;

    /* div dst src|imm */
    case div_ins:
      if (node_v2 == imm_int)
        c_code += "BPF_ALU64_IMM(BPF_DIV, " +
                  get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU64_REG(BPF_DIV, " +
                   get_reg_str(node_v1, id1) + ", " +
                   get_reg_str(node_v2, id2) + "),\n";
    break;

    /* or dst src|imm */
    case or_ins:
      if (node_v2 == imm_int)
        c_code += "BPF_ALU64_IMM(BPF_OR, "  +
                  get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU64_REG(BPF_OR, "  +
                   get_reg_str(node_v1, id1) + ", " +
                   get_reg_str(node_v2, id2) + "),\n";
    break;

    /* and dst src|imm */
    case and_ins:
      if (node_v2 == imm_int)
        c_code += "BPF_ALU64_IMM(BPF_AND, " +
                  get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU64_REG(BPF_AND, " +
                   get_reg_str(node_v1, id1) + ", " +
                   get_reg_str(node_v2, id2) + "),\n";
    break;

    /* lsh dst src|imm */
    case lsh:
      if (node_v2 == imm_int)
        c_code += "BPF_ALU64_IMM(BPF_LSH, " +
                  get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU64_REG(BPF_LSH, " +
                   get_reg_str(node_v1, id1) + ", " +
                   get_reg_str(node_v2, id2) + "),\n";
    break;

    /* rsh dst src|imm */
    case rsh:
      if (node_v2 == imm_int)
        c_code += "BPF_ALU64_IMM(BPF_RSH, " +
                  get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU64_REG(BPF_RSH, " +
                   get_reg_str(node_v1, id1) + ", " +
                   get_reg_str(node_v2, id2) + "),\n";
    break;

    /* neg dst */
    case neg:
       c_code += "BPF_ALU64_IMM(BPF_NEG, " + get_reg_str(node_v1, id1) +
                 ", 0),\n";
    break;

    /* mod dst src|imm */
    case mod:
      if (node_v2 == imm_int)
        c_code += "BPF_ALU64_IMM(BPF_MOD, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU64_REG(BPF_MOD, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + "),\n";
    break;

    /* xor dst src|imm */
    case xor_ins:
      if (node_v2 == imm_int)
        c_code += "BPF_ALU64_IMM(BPF_XOR, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU64_REG(BPF_XOR, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + "),\n";
    break;

    /* mov dst src|imm */
    case mov:
      if (node_v2 == imm_int)
        c_code += "BPF_ALU64_IMM(BPF_MOV, " + get_reg_str(node_v1, id1) + ", "
                   + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
        c_code += "BPF_ALU64_REG(BPF_MOV, " + get_reg_str(node_v1, id1) + ", "
                  + get_reg_str(node_v2, id2) + "),\n";
     break;

    /* arsh dst src|imm */
    case arsh:
      if (node_v2 == imm_int)
        c_code += "BPF_ALU64_IMM(BPF_ARSH, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU64_REG(BPF_ARSH, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + "),\n";
    break;

    /* 32-bit: */
    /* add32 dst src|imm */
    case add32:
      if (node_v2 == imm_int)
        c_code += "BPF_ALU32_IMM(BPF_ADD, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU32_REG(BPF_ADD, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + "),\n";
    break;

    /* sub32 dst src|imm */
    case sub32:
      if (node_v2 == imm_int)
        c_code += "BPF_ALU32_IMM(BPF_SUB, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU32_REG(BPF_SUB, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + "),\n";
    break;

    /* mul32 dst src|imm */
    case mul32:
      if (node_v2 == imm_int)
        c_code += "BPF_ALU32_IMM(BPF_MUL, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU32_REG(BPF_MUL, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + "),\n";
    break;

    /* div32 dst src|imm */
    case div32:
      if (node_v2 == imm_int)
        c_code += "BPF_ALU32_IMM(BPF_DIV, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU32_REG(BPF_DIV, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + "),\n";
    break;

    /* or32 dst src|imm */
    case or32:
      if (node_v2 == imm_int)
        c_code += "BPF_ALU32_IMM(BPF_OR, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU32_REG(BPF_OR, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + "),\n";
    break;

    /* and32 dst src|imm */
    case and32:
      if (node_v2 == imm_int)
        c_code += "BPF_ALU32_IMM(BPF_AND, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU32_REG(BPF_AND, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + "),\n";
    break;

    /* lsh32 dst src|imm */
    case lsh32:
      if (node_v2 == imm_int)
        c_code += "BPF_ALU32_IMM(BPF_LSH, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU32_REG(BPF_LSH, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + "),\n";
    break;

    /* rsh32 dst src|imm */
    case rsh32:
      if (node_v2 == imm_int)
        c_code += "BPF_ALU32_IMM(BPF_RSH, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU32_REG(BPF_RSH, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + "),\n";
    break;

    /* neg32 dst */
    case neg32:
       c_code += "BPF_ALU32_IMM(BPF_NEG, " + get_reg_str(node_v1, id1)
                 + ", 0),\n";
    break;

    /* mod32 dst src|imm */
    case mod32:
      if (node_v2 == imm_int)
        c_code += "BPF_ALU32_IMM(BPF_MOD, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU32_REG(BPF_MOD, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + "),\n";
    break;

    /* xor32 dst src|imm */
    case xor32:
      if (node_v2 == imm_int)
        c_code += "BPF_ALU32_IMM(BPF_XOR, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU32_REG(BPF_XOR, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + "),\n";
    break;

    /* mov32 dst src|imm */
    case mov32:
      if (node_v2 == imm_int)
        c_code += "BPF_ALU32_IMM(BPF_MOV, " + get_reg_str(node_v1, id1) + ", "
                   + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
        c_code += "BPF_ALU32_REG(BPF_MOV, " + get_reg_str(node_v1, id1) + ", "
                  + get_reg_str(node_v2, id2) + "),\n";
     break;

    /* arsh32 dst src|imm */
    case arsh32:
      if (node_v2 == imm_int)
        c_code += "BPF_ALU32_IMM(BPF_ARSH, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + "),\n";
      else
         c_code += "BPF_ALU32_REG(BPF_ARSH, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + "),\n";
    break;

    /* le16 dst src|imm */
    case le16:
       c_code += "BPF_ENDIAN(BPF_TO_LE, " + get_reg_str(node_v1, id1)
                 + ", 16),\n";
    break;

    /* le32 dst src|imm */
    case le32:
       c_code += "BPF_ENDIAN(BPF_TO_LE, " + get_reg_str(node_v1, id1)
                 + ", 32),\n";
    break;

    /* le64 dst src|imm */
    case le64:
       c_code += "BPF_ENDIAN(BPF_TO_LE, " + get_reg_str(node_v1, id1)
                 + ", 64),\n";
    break;

    /* be16 dst src|imm */
    case be16:
       c_code += "BPF_ENDIAN(BPF_TO_BE, " + get_reg_str(node_v1, id1)
                 + ", 16),\n";
    break;

    /* be32 dst src|imm */
    case be32:
       c_code += "BPF_ENDIAN(BPF_TO_BE, " + get_reg_str(node_v1, id1)
                 + ", 32),\n";
    break;

    /* be64 dst src|imm */
    case be64:
       c_code += "BPF_ENDIAN(BPF_TO_BE, " + get_reg_str(node_v1, id1)
                 + ", 64),\n";
    break;

    /* addx16 dst src off */
    case addx16:
       c_code += "BPF_ATOMIC_OP(16, BPF_ADD, " + get_reg_str(node_v1, id1) +
                 ", " + get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* addx32 dst src off */
    case addx32:
       c_code += "BPF_ATOMIC_OP(32, BPF_ADD, " + get_reg_str(node_v1, id1) +
                 ", " + get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* addx64 dst src off */
    case addx64:
       c_code += "BPF_ATOMIC_OP(64, BPF_ADD, " + get_reg_str(node_v1, id1) +
                 ", " + get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* andx16 dst src off */
    case andx16:
       c_code += "BPF_ATOMIC_OP(16, BPF_AND, " + get_reg_str(node_v1, id1) +
                 ", " +  get_reg_str(node_v2, id2) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* andx32 dst src off */
    case andx32:
       c_code += "BPF_ATOMIC_OP(32, BPF_AND, " + get_reg_str(node_v1, id1) +
                 ", " + get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* andx64 dst src off */
    case andx64:
       c_code += "BPF_ATOMIC_OP(64, BPF_AND, " + get_reg_str(node_v1, id1) +
                 ", " + get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* orx16 dst src off */
    case orx16:
       c_code += "BPF_ATOMIC_OP(16, BPF_OR, " + get_reg_str(node_v1, id1) +
                 ", " + get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* orx32 dst src off */
    case orx32:
       c_code += "BPF_ATOMIC_OP(32, BPF_OR, " + get_reg_str(node_v1, id1) +
                 ", " + get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* orx64 dst src off */
    case orx64:
       c_code += "BPF_ATOMIC_OP(64, BPF_OR, " + get_reg_str(node_v1, id1) +
                 ", " + get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* xorx16 dst src off */
    case xorx16:
       c_code += "BPF_ATOMIC_OP(16, BPF_XOR, " + get_reg_str(node_v1, id1) +
                 ", " + get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* xorx32 dst src off */
    case xorx32:
       c_code += "BPF_ATOMIC_OP(32, BPF_XOR, " + get_reg_str(node_v1, id1) +
                 ", " + get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* xorx64 dst src off */
    case xorx64:
       c_code += "BPF_ATOMIC_OP(64, BPF_XOR, " + get_reg_str(node_v1, id1) +
                 ", " + get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* addfx16 dst src off */
    case addfx16:
       c_code += "BPF_ATOMIC_OP(16, BPF_ADD | BPF_FETCH, " +
                 get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* addfx32 dst src off */
    case addfx32:
       c_code += "BPF_ATOMIC_OP(32, BPF_ADD | BPF_FETCH, " +
                 get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* addfx64 dst src off */
    case addfx64:
       c_code += "BPF_ATOMIC_OP(64, BPF_ADD | BPF_FETCH, " +
                 get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* andfx16 dst src off */
    case andfx16:
       c_code += "BPF_ATOMIC_OP(16, BPF_AND | BPF_FETCH, " +
                 get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* andfx32 dst src off */
    case andfx32:
       c_code += "BPF_ATOMIC_OP(32, BPF_AND | BPF_FETCH, " +
                 get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* andfx64 dst src off */
    case andfx64:
       c_code += "BPF_ATOMIC_OP(64, BPF_AND | BPF_FETCH, " +
                  get_reg_str(node_v1, id1) + ", " +
                  get_reg_str(node_v2, id2) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* orfx16 dst src off */
    case orfx16:
       c_code += "BPF_ATOMIC_OP(16, BPF_OR | BPF_FETCH, " +
                 get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* orfx32 dst src off */
    case orfx32:
       c_code += "BPF_ATOMIC_OP(32, BPF_OR | BPF_FETCH, " +
                 get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* orfx64 dst src off */
    case orfx64:
       c_code += "BPF_ATOMIC_OP(64, BPF_OR | BPF_FETCH, " +
                 get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* xorfx16 dst src off */
    case xorfx16:
       c_code += "BPF_ATOMIC_OP(16, BPF_XOR | BPF_FETCH, " +
                 get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* xorfx32 dst src off */
    case xorfx32:
       c_code += "BPF_ATOMIC_OP(32, BPF_XOR | BPF_FETCH, " +
                 get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* xorfx64 dst src off */
    case xorfx64:
       c_code += "BPF_ATOMIC_OP(64, BPF_XOR | BPF_FETCH, " +
                 get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* xchgx16 dst src off */
    case xchgx16:
       c_code += "BPF_ATOMIC_OP(16, BPF_XCHG, " +
                 get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* xchgx32 dst src off */
    case xchgx32:
       c_code += "BPF_ATOMIC_OP(32, BPF_XCHG, " +
                 get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* xchgx64 dst src off */
    case xchgx64:
       c_code += "BPF_ATOMIC_OP(64, BPF_XCHG, " + get_reg_str(node_v1, id1) +
                 ", " + get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* cmpxchgx16 dst src off */
    case cmpxchgx16:
       c_code += "BPF_ATOMIC_OP(16, BPF_CMPXCHG, " + get_reg_str(node_v1, id1)
                 + ", " + get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* cmpxchgx32 dst src off */
    case cmpxchgx32:
       c_code += "BPF_ATOMIC_OP(32, BPF_CMPXCHG, " + get_reg_str(node_v1, id1)
                 + ", " + get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* cmpxchgx64 dst src off */
    case cmpxchgx64:
       c_code += "BPF_ATOMIC_OP(64, BPF_CMPXCHG, " + get_reg_str(node_v1, id1)
                 + ", " + get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* ldmapfd dst imm  */
    case ldmapfd:
       c_code += "BPF_LD_MAP_FD(" + get_reg_str(node_v1, id1) + ", " +
                 std::to_string(get_val<int>(node_v2, id2)) + "),\n";
    break;

    /* ld64 dst imm  */
    case ld64:
       c_code += "BPF_LD_IMM64(" + get_reg_str(node_v1, id1) + ", " +
                 std::to_string(get_val<int>(node_v2, id2)) + "),\n";
    break;

    /* ldabs8 imm  */
    case ldabs8:
       c_code += "BPF_LD_ABS(8, " + std::to_string(get_val<int>(node_v1, id1))
                 + "),\n";
    break;

    /* ldabs16 imm  */
    case ldabs16:
       c_code += "BPF_LD_ABS(16, " + std::to_string(get_val<int>(node_v1, id1))
                 + "),\n";
    break;

    /* ldabs32 imm  */
    case ldabs32:
       c_code += "BPF_LD_ABS(32, " + std::to_string(get_val<int>(node_v1, id1))
                 + "),\n";
    break;

    /* ldabs64 imm  */
    case ldabs64:
       c_code += "BPF_LD_ABS(64, " + std::to_string(get_val<int>(node_v1, id1))
                 + "),\n";
    break;

    /* ldind8 src imm  */
    case ldind8:
       c_code += "BPF_LD_IND(8, " + get_reg_str(node_v1, id1) + ", " +
                 std::to_string(get_val<int>(node_v2, id2)) + "),\n";
    break;

    /* ldind16 src imm  */
    case ldind16:
       c_code += "BPF_LD_IND(16, " + get_reg_str(node_v1, id1) + ", " +
                 std::to_string(get_val<int>(node_v2, id2)) + "),\n";
    break;

    /* ldind32 src imm  */
    case ldind32:
       c_code += "BPF_LD_IND(32, " + get_reg_str(node_v1, id1) + ", " +
                 std::to_string(get_val<int>(node_v2, id2)) + "),\n";
    break;

    /* ldind64 src imm  */
    case ldind64:
       c_code += "BPF_LD_IND(64, " + get_reg_str(node_v1, id1) + ", " +
                 std::to_string(get_val<int>(node_v2, id2)) + "),\n";
    break;

    /* ldx8 dst src off  */
    case ldx8:
       c_code += "BPF_LDX_MEM(8, " + get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* ldx16 dst src off  */
    case ldx16:
       c_code += "BPF_LDX_MEM(16, " + get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* ldx32 dst src off  */
    case ldx32:
       c_code += "BPF_LDX_MEM(32, " + get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* ldx64 dst src off  */
    case ldx64:
       c_code += "BPF_LDX_MEM(64, " + get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* st8 dst off imm  */
    case st8:
       c_code += "BPF_ST_MEM(8, " + get_reg_str(node_v1, id1) + ", " +
                 std::to_string((__s16)get_val<int>(node_v2, id2)) + ", " +
                 std::to_string(get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* st16 dst off imm   */
    case st16:
       c_code += "BPF_ST_MEM(16, " + get_reg_str(node_v1, id1) + ", " +
                 std::to_string((__s16)get_val<int>(node_v2, id2)) + ", " +
                 std::to_string(get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* st32 dst off imm   */
    case st32:
       c_code += "BPF_ST_MEM(32, " + get_reg_str(node_v1, id1) + ", " +
                 std::to_string((__s16)get_val<int>(node_v2, id2)) + ", " +
                 std::to_string(get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* st64 dst off imm   */
    case st64:
       c_code += "BPF_ST_MEM(64, " + get_reg_str(node_v1, id1) + ", " +
                 std::to_string((__s16)get_val<int>(node_v2, id2)) + ", " +
                 std::to_string(get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* stx8 dst src off  */
    case stx8:
       c_code += "BPF_STX_MEM(8, " + get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* stx16 dst src off  */
    case stx16:
       c_code += "BPF_STX_MEM(16, " + get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* stx32 dst src off  */
    case stx32:
       c_code += "BPF_STX_MEM(32, " + get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* stx64 dst src off  */
    case stx64:
       c_code += "BPF_STX_MEM(64, " + get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* stxx8 dst src off  */
    case stxx8:
       c_code += "BPF_STX_XADD(8, " + get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* stxx16 dst src off  */
    case stxx16:
       c_code += "BPF_STX_XADD(16, " + get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* stxx32 dst src off  */
    case stxx32:
       c_code += "BPF_STX_XADD(32, " + get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* stxx64 dst src off  */
    case stxx64:
       c_code += "BPF_STX_XADD(64, " + get_reg_str(node_v1, id1) + ", " +
                 get_reg_str(node_v2, id2) + ", " +
                 std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* ja off */
    case ja:
       c_code += "BPF_JMP_A(" +
                 std::to_string((__s16)get_val<int>(node_v1, id1)) + "),\n";
    break;

    /* jeq dst src|imm off */
    case jeq:
      if (node_v2 == imm_int)
        c_code += "BPF_JMP_IMM(BPF_JEQ, " + get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP_REG(BPF_JEQ, " + get_reg_str(node_v1, id1) + ", " +
                   get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* jgt dst src|imm off */
    case jgt:
      if (node_v2 == imm_int)
        c_code += "BPF_JMP_IMM(BPF_JGT, " + get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP_REG(BPF_JGT, " + get_reg_str(node_v1, id1) + ", " +
                   get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* jge dst src|imm off */
    case jge:
      if (node_v2 == imm_int)
        c_code += "BPF_JMP_IMM(BPF_JGE, " + get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP_REG(BPF_JGE, " + get_reg_str(node_v1, id1) + ", " +
                   get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* jlt dst src|imm off */
    case jlt:
      if (node_v2 == imm_int)
        c_code += "BPF_JMP_IMM(BPF_JLT, " + get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP_REG(BPF_JLT, " + get_reg_str(node_v1, id1) + ", " +
                   get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* jle dst src|imm off */
    case jle:
      if (node_v2 == imm_int)
        c_code += "BPF_JMP_IMM(BPF_JLE, " + get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP_REG(BPF_JLE, " + get_reg_str(node_v1, id1) + ", " +
                   get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* jset dst src|imm off */
    case jset:
      if (node_v2 == imm_int)
        c_code += "BPF_JMP_IMM(BPF_JSET, " + get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP_REG(BPF_JSET, " + get_reg_str(node_v1, id1) + ", " +
                   get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* jne dst src|imm off */
    case jne:
      if (node_v2 == imm_int)
        c_code += "BPF_JMP_IMM(BPF_JNE, " + get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP_REG(BPF_JNE, " + get_reg_str(node_v1, id1) + ", " +
                   get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* jsgt dst src|imm off */
    case jsgt:
      if (node_v2 == imm_int)
        c_code += "BPF_JMP_IMM(BPF_JSGT, " + get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP_REG(BPF_JSGT, " + get_reg_str(node_v1, id1) + ", " +
                   get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* jsge dst src|imm off */
    case jsge:
      if (node_v2 == imm_int)
        c_code += "BPF_JMP_IMM(BPF_JSGE, " + get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP_REG(BPF_JSGE, " + get_reg_str(node_v1, id1) + ", " +
                   get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* jslt dst src|imm off */
    case jslt:
      if (node_v2 == imm_int)
        c_code += "BPF_JMP_IMM(BPF_JSLT, " + get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP_REG(BPF_JSLT, " + get_reg_str(node_v1, id1) + ", " +
                   get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* jsle dst src|imm off */
    case jsle:
      if (node_v2 == imm_int)
        c_code += "BPF_JMP_IMM(BPF_JSLE, " + get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP_REG(BPF_JSLE, " + get_reg_str(node_v1, id1) + ", " +
                   get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* call imm */
    case call:
      error("error: call: instruction not yet supported.");
    break;

    /* rel imm */
    case rel:
      c_code += "BPF_CALL_REL(" + std::to_string(get_val<int>(node_v1, id1)) +
                "),\n";
    break;

    /* exit */
    case exit_ins:
      c_code += "BPF_EXIT_INSN(),\n";
    break;

    /* jeq32 dst src|imm off */
    case jeq32:
      if (node_v2 == imm_int)
        c_code += "BPF_JMP32_IMM(BPF_JEQ, " + get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP32_REG(BPF_JEQ, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* jgt32 dst src|imm off */
    case jgt32:
      if (node_v2 == imm_int)
        c_code += "BPF_JMP32_IMM(BPF_JGT, " + get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP32_REG(BPF_JGT, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* jge32 dst src|imm off */
    case jge32:
      if (node_v2 == imm_int)
        c_code += "BPF_JMP32_IMM(BPF_JGE, " + get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP32_REG(BPF_JGE, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* jlt32 dst src|imm off */
    case jlt32:
      if (node_v2 == imm_int)
        c_code += "BPF_JMP32_IMM(BPF_JLT, " + get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP32_REG(BPF_JLT, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* jle32 dst src|imm off */
    case jle32:
      if (node_v2 == imm_int)
        c_code += "BPF_JMP32_IMM(BPF_JLE, " + get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP32_REG(BPF_JLE, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* jset32 dst src|imm off */
    case jset32:
      if (node_v2 == imm_int)
        c_code += "BPF_JMP32_IMM(BPF_JSET, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP32_REG(BPF_JSET, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* jne32 dst src|imm off */
    case jne32:
      if (node_v2 == imm_int)
        c_code += "BPF_JMP32_IMM(BPF_JNE, " + get_reg_str(node_v1, id1) + ", " +
                  std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP32_REG(BPF_JNE, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* jsgt32 dst src|imm off */
    case jsgt32:
      if (node_v2 == imm_int)
        c_code += "BPF_JMP32_IMM(BPF_JSGT, " + get_reg_str(node_v1, id1) + ", "
                   + std::to_string(get_val<int>(node_v2, id2)) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP32_REG(BPF_JSGT, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* jsge32 dst src|imm off */
    case jsge32:
      if (node_v2 == imm_int)
        c_code += "BPF_JMP32_IMM(BPF_JSGE, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP32_REG(BPF_JSGE, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* jslt32 dst src|imm off */
    case jslt32:
      if (node_v2 == imm_int)
        c_code += "BPF_JMP32_IMM(BPF_JSLT, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP32_REG(BPF_JSLT, " + get_reg_str(node_v1, id1) + ", "
                   + get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* jsle32 dst src|imm off */
    case jsle32:
      if (node_v2 == imm_int)
        c_code += "BPF_JMP32_IMM(BPF_JSLE, " + get_reg_str(node_v1, id1) + ", "
                  + std::to_string(get_val<int>(node_v2, id2)) + ", " +
                  std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
      else
         c_code += "BPF_JMP32_REG(BPF_JSLE, " +
                   get_reg_str(node_v1, id1) + ", " +
                   get_reg_str(node_v2, id2) + ", " +
                   std::to_string((__s16)get_val<int>(node_v3, id3)) + "),\n";
    break;

    /* zext dst */
    case zext:
      c_code += "BPF_ZEXT_REG(" + get_reg_str(node_v1, id1) + "),\n";
    break;

    case regs: case imm_int:
    break;

    default:
      error("Internal code generation error: uncovered case for: ",
            pp_node(node_v));
    }
  }

  c_code += "};\n";

  std::ofstream ofs;
  ofs.open(out_fname);
  if (!ofs.is_open())
    error("error: std::ofstream::open() failed opening file: `", out_fname,
          "`: ", strerror(errno));
  ofs<<c_code;
  ofs.close();
}
