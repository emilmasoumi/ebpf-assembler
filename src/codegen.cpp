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

static inline __u8 map_reg(int r) {
	if      (r == 0)  return BPF_REG_0;
	else if (r == 1)  return BPF_REG_1;
	else if (r == 2)  return BPF_REG_2;
	else if (r == 3)  return BPF_REG_3;
	else if (r == 4)  return BPF_REG_4;
	else if (r == 5)  return BPF_REG_5;
	else if (r == 6)  return BPF_REG_6;
	else if (r == 7)  return BPF_REG_7;
	else if (r == 8)  return BPF_REG_8;
	else if (r == 9)  return BPF_REG_9;
	else if (r == 10) return BPF_REG_10;
	else error("map_reg(): unknown register ", r);
	return -1;
}

template <typename T>
static inline T get_val(std::any n) {
	if (IS_OF_TYPE(n, imm_int))        return std::any_cast<imm_int>(&n)->val;
	else if (IS_OF_TYPE(n, imm_float)) return std::any_cast<imm_float>(&n)->val;
	else error("get_val(): not an immediate: ", pp_subtype(n));
	return -1;
}

static inline __u8 get_reg(std::any n) {
	if (IS_OF_TYPE(n, regs)) return map_reg(std::any_cast<regs>(&n)->reg);
	else error("get_reg(): not a register: ", pp_subtype(n));
	return -1;
}

static inline std::string get_reg_str(std::any n) {
	int r = 0;
	if (IS_OF_TYPE(n, regs)) r = std::any_cast<regs>(&n)->reg;
	else error("get_reg_str(): not a register: ", pp_subtype(n));

	if      (r == 0)  return "BPF_REG_0";
	else if (r == 1)  return "BPF_REG_1";
	else if (r == 2)  return "BPF_REG_2";
	else if (r == 3)  return "BPF_REG_3";
	else if (r == 4)  return "BPF_REG_4";
	else if (r == 5)  return "BPF_REG_5";
	else if (r == 6)  return "BPF_REG_6";
	else if (r == 7)  return "BPF_REG_7";
	else if (r == 8)  return "BPF_REG_8";
	else if (r == 9)  return "BPF_REG_9";
	else if (r == 10) return "BPF_REG_10";
	return "";
}

void codegen(std::string out_fname) {

	uint size;
	ast_t node;
	std::any node_v, node_v1, node_v2, node_v3;
  Symbol type;
	uint i, prog_len, ops;
	// errors reported by valgrind are subdued when assigning a smaller
	// ``prog`` array size.
	struct bpf_insn prog[1000000];

	size     = absyn_tree.size();
	prog_len = 0;

	for (i=0; i<size; i++) {
    node   = absyn_tree[i];
    node_v = node.node_v;
		type   = node.type;

		if (type == instr)
			ops = get_ops(node_v);
		else
			ops = 0;

		if (ops == 1) {
			node_v1 = absyn_tree[i+1].node_v;
		}
		else if (ops == 2) {
			node_v1 = absyn_tree[i+1].node_v;
			node_v2 = absyn_tree[i+2].node_v;
		}
		else if (ops == 3) {
			node_v1 = absyn_tree[i+1].node_v;
			node_v2 = absyn_tree[i+2].node_v;
			node_v3 = absyn_tree[i+3].node_v;
		}

		/* ALU instructions: */
		/* 64-bit: */
		/* add dst src|imm */
		if (IS_OF_TYPE(node_v, add)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				prog[prog_len++] = BPF_ALU64_IMM(BPF_ADD, get_reg(node_v1),
				                                 get_val<int>(node_v2));
		  else
		 	  prog[prog_len++] = BPF_ALU64_REG(BPF_ADD, get_reg(node_v1),
				                                          get_reg(node_v2));
    }

		/* sub dst src|imm */
		else if (IS_OF_TYPE(node_v, sub)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				prog[prog_len++] = BPF_ALU64_IMM(BPF_SUB, get_reg(node_v1),
				                                 get_val<int>(node_v2));
		  else
		 	  prog[prog_len++] = BPF_ALU64_REG(BPF_SUB, get_reg(node_v1),
				                                          get_reg(node_v2));
    }

		/* mul dst src|imm */
		else if (IS_OF_TYPE(node_v, mul)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				prog[prog_len++] = BPF_ALU64_IMM(BPF_MUL, get_reg(node_v1),
				                                 get_val<int>(node_v2));
		  else
		 	  prog[prog_len++] = BPF_ALU64_REG(BPF_MUL, get_reg(node_v1),
				                                          get_reg(node_v2));
    }

		/* div dst src|imm */
		else if (IS_OF_TYPE(node_v, div_ins)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				prog[prog_len++] = BPF_ALU64_IMM(BPF_DIV, get_reg(node_v1),
				                                 get_val<int>(node_v2));
		  else
		 	  prog[prog_len++] = BPF_ALU64_REG(BPF_DIV, get_reg(node_v1),
				                                          get_reg(node_v2));
    }

		/* or dst src|imm */
		else if (IS_OF_TYPE(node_v, or_ins)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				prog[prog_len++] = BPF_ALU64_IMM(BPF_OR, get_reg(node_v1),
				                                 get_val<int>(node_v2));
		  else
		 	  prog[prog_len++] = BPF_ALU64_REG(BPF_OR, get_reg(node_v1),
				                                         get_reg(node_v2));
    }

		/* and dst src|imm */
		else if (IS_OF_TYPE(node_v, and_ins)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				prog[prog_len++] = BPF_ALU64_IMM(BPF_AND, get_reg(node_v1),
				                                 get_val<int>(node_v2));
		  else
		 	  prog[prog_len++] = BPF_ALU64_REG(BPF_AND, get_reg(node_v1),
				                                          get_reg(node_v2));
    }

		/* lsh dst src|imm */
		else if (IS_OF_TYPE(node_v, lsh)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				prog[prog_len++] = BPF_ALU64_IMM(BPF_LSH, get_reg(node_v1),
				                                 get_val<int>(node_v2));
		  else
		 	  prog[prog_len++] = BPF_ALU64_REG(BPF_LSH, get_reg(node_v1),
				                                          get_reg(node_v2));
    }

		/* rsh dst src|imm */
		else if (IS_OF_TYPE(node_v, rsh)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				prog[prog_len++] = BPF_ALU64_IMM(BPF_RSH, get_reg(node_v1),
				                                 get_val<int>(node_v2));
		  else
		 	  prog[prog_len++] = BPF_ALU64_REG(BPF_RSH, get_reg(node_v1),
				                                          get_reg(node_v2));
    }

		/* neg dst src|imm */
		else if (IS_OF_TYPE(node_v, neg)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				prog[prog_len++] = BPF_ALU64_IMM(BPF_NEG, get_reg(node_v1), 0);
    }

		/* mod dst src|imm */
		else if (IS_OF_TYPE(node_v, mod)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				prog[prog_len++] = BPF_ALU64_IMM(BPF_MOD, get_reg(node_v1),
				                                 get_val<int>(node_v2));
		  else
		 	  prog[prog_len++] = BPF_ALU64_REG(BPF_MOD, get_reg(node_v1),
				                                          get_reg(node_v2));
    }

		/* xor dst src|imm */
		else if (IS_OF_TYPE(node_v, xor_ins)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				prog[prog_len++] = BPF_ALU64_IMM(BPF_XOR, get_reg(node_v1),
				                                 get_val<int>(node_v2));
		  else
		 	  prog[prog_len++] = BPF_ALU64_REG(BPF_XOR, get_reg(node_v1),
				                                          get_reg(node_v2));
    }

		/* mov dst src|imm */
		else if (IS_OF_TYPE(node_v, mov)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				prog[prog_len++] = BPF_ALU64_IMM(BPF_MOV, get_reg(node_v1),
				                                 get_val<int>(node_v2));
		  else
		 	  prog[prog_len++] = BPF_ALU64_REG(BPF_MOV, get_reg(node_v1),
				                                          get_reg(node_v2));
    }

		/* arsh dst src|imm */
		else if (IS_OF_TYPE(node_v, arsh)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				prog[prog_len++] = BPF_ALU64_IMM(BPF_ARSH, get_reg(node_v1),
				                                 get_val<int>(node_v2));
		  else
		 	  prog[prog_len++] = BPF_ALU64_REG(BPF_ARSH, get_reg(node_v1),
				                                           get_reg(node_v2));
    }

		/* 32-bit: */
		/* add32 dst src|imm */
		if (IS_OF_TYPE(node_v, add32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				prog[prog_len++] = BPF_ALU32_IMM(BPF_ADD, get_reg(node_v1),
				                                 get_val<int>(node_v2));
		  else
		 	  prog[prog_len++] = BPF_ALU32_REG(BPF_ADD, get_reg(node_v1),
				                                          get_reg(node_v2));
    }

		/* sub32 dst src|imm */
		else if (IS_OF_TYPE(node_v, sub32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				prog[prog_len++] = BPF_ALU32_IMM(BPF_SUB, get_reg(node_v1),
				                                 get_val<int>(node_v2));
		  else
		 	  prog[prog_len++] = BPF_ALU32_REG(BPF_SUB, get_reg(node_v1),
				                                          get_reg(node_v2));
		}

		/* mul32 dst src|imm */
		else if (IS_OF_TYPE(node_v, mul32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				prog[prog_len++] = BPF_ALU32_IMM(BPF_MUL, get_reg(node_v1),
				                                 get_val<int>(node_v2));
		  else
		 	  prog[prog_len++] = BPF_ALU32_REG(BPF_MUL, get_reg(node_v1),
				                                          get_reg(node_v2));
		}

		/* div32 dst src|imm */
		else if (IS_OF_TYPE(node_v, div32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				prog[prog_len++] = BPF_ALU32_IMM(BPF_DIV, get_reg(node_v1),
				                                 get_val<int>(node_v2));
		  else
		 	  prog[prog_len++] = BPF_ALU32_REG(BPF_DIV, get_reg(node_v1),
				                                          get_reg(node_v2));
		}

		/* or32 dst src|imm */
		else if (IS_OF_TYPE(node_v, or32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				prog[prog_len++] = BPF_ALU32_IMM(BPF_OR, get_reg(node_v1),
				                                 get_val<int>(node_v2));
		  else
		 	  prog[prog_len++] = BPF_ALU32_REG(BPF_OR, get_reg(node_v1),
				                                          get_reg(node_v2));
		}

		/* and32 dst src|imm */
		else if (IS_OF_TYPE(node_v, and32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				prog[prog_len++] = BPF_ALU32_IMM(BPF_AND, get_reg(node_v1),
				                                 get_val<int>(node_v2));
		  else
		 	  prog[prog_len++] = BPF_ALU32_REG(BPF_AND, get_reg(node_v1),
				                                          get_reg(node_v2));
		}

		/* lsh32 dst src|imm */
		else if (IS_OF_TYPE(node_v, lsh32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				prog[prog_len++] = BPF_ALU32_IMM(BPF_LSH, get_reg(node_v1),
				                                 get_val<int>(node_v2));
		  else
		 	  prog[prog_len++] = BPF_ALU32_REG(BPF_LSH, get_reg(node_v1),
				                                          get_reg(node_v2));
		}

		/* rsh32 dst src|imm */
		else if (IS_OF_TYPE(node_v, rsh32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				prog[prog_len++] = BPF_ALU32_IMM(BPF_RSH, get_reg(node_v1),
				                                 get_val<int>(node_v2));
		  else
		 	  prog[prog_len++] = BPF_ALU32_REG(BPF_RSH, get_reg(node_v1),
				                                          get_reg(node_v2));
		}

		/* neg32 dst */
		else if (IS_OF_TYPE(node_v, neg32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				prog[prog_len++] = BPF_ALU32_IMM(BPF_NEG, get_reg(node_v1), 0);
		}

		/* mod32 dst src|imm */
		else if (IS_OF_TYPE(node_v, mod32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				prog[prog_len++] = BPF_ALU32_IMM(BPF_MOD, get_reg(node_v1),
				                                 get_val<int>(node_v2));
		  else
		 	  prog[prog_len++] = BPF_ALU32_REG(BPF_MOD, get_reg(node_v1),
				                                          get_reg(node_v2));
		}

		/* xor32 dst src|imm */
		else if (IS_OF_TYPE(node_v, xor32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				prog[prog_len++] = BPF_ALU32_IMM(BPF_XOR, get_reg(node_v1),
				                                 get_val<int>(node_v2));
		  else
		 	  prog[prog_len++] = BPF_ALU32_REG(BPF_XOR, get_reg(node_v1),
				                                          get_reg(node_v2));
		}

		/* mov32 dst src|imm */
		else if (IS_OF_TYPE(node_v, mov32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				prog[prog_len++] = BPF_ALU32_IMM(BPF_MOV, get_reg(node_v1),
				                                 get_val<int>(node_v2));
		  else
		 	  prog[prog_len++] = BPF_ALU32_REG(BPF_MOV, get_reg(node_v1),
				                                          get_reg(node_v2));
		}

		/* arsh32 dst src|imm */
		else if (IS_OF_TYPE(node_v, arsh32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				prog[prog_len++] = BPF_ALU32_IMM(BPF_ARSH, get_reg(node_v1),
				                                 get_val<int>(node_v2));
		  else
		 	  prog[prog_len++] = BPF_ALU32_REG(BPF_ARSH, get_reg(node_v1),
				                                           get_reg(node_v2));
		}

		/* mov32 dst src|imm */
		else if (IS_OF_TYPE(node_v, mov32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
			  prog[prog_len++] = BPF_MOV32_IMM(get_reg(node_v1),
				                                 get_val<int>(node_v2));
			else
			  prog[prog_len++] = BPF_MOV32_REG(get_reg(node_v1), get_reg(node_v2));
		}

		/* Endianess conversion (Byteswap) instructions: */
		/* le16 dst */
    else if (IS_OF_TYPE(node_v, le16)) {
			prog[prog_len++] = BPF_ENDIAN(BPF_TO_LE, get_reg(node_v1), 16);
		}

		/* le32 dst */
    else if (IS_OF_TYPE(node_v, le32)) {
			prog[prog_len++] = BPF_ENDIAN(BPF_TO_LE, get_reg(node_v1), 32);
		}

		/* le64 dst */
    else if (IS_OF_TYPE(node_v, le64)) {
			prog[prog_len++] = BPF_ENDIAN(BPF_TO_LE, get_reg(node_v1), 64);
		}

		/* be16 dst */
    else if (IS_OF_TYPE(node_v, be16)) {
			prog[prog_len++] = BPF_ENDIAN(BPF_TO_BE, get_reg(node_v1), 16);
		}

		/* be32 dst */
    else if (IS_OF_TYPE(node_v, be32)) {
			prog[prog_len++] = BPF_ENDIAN(BPF_TO_BE, get_reg(node_v1), 32);
		}

		/* be64 dst */
    else if (IS_OF_TYPE(node_v, be64)) {
			prog[prog_len++] = BPF_ENDIAN(BPF_TO_BE, get_reg(node_v1), 64);
		}

		/* Atomic operations: */
    /* addx16 dst src off */
		else if (IS_OF_TYPE(node_v, addx16)) {
			prog[prog_len++] = BPF_ATOMIC_OP(16, BPF_ADD,
				                               get_reg(node_v1), get_reg(node_v2),
																			 (__s16)get_val<int>(node_v3));
		}

    /* addx32 dst src off */
		else if (IS_OF_TYPE(node_v, addx32)) {
			prog[prog_len++] = BPF_ATOMIC_OP(32, BPF_ADD,
				                               get_reg(node_v1), get_reg(node_v2),
																			 (__s16)get_val<int>(node_v3));
		}

    /* addx64 dst src off */
		else if (IS_OF_TYPE(node_v, addx64)) {
			prog[prog_len++] = BPF_ATOMIC_OP(64, BPF_ADD,
				                               get_reg(node_v1), get_reg(node_v2),
																			 (__s16)get_val<int>(node_v3));
		}

    /* andx16 dst src off */
		else if (IS_OF_TYPE(node_v, andx16)) {
			prog[prog_len++] = BPF_ATOMIC_OP(16, BPF_AND,
				                               get_reg(node_v1), get_reg(node_v2),
																			 (__s16)get_val<int>(node_v3));
		}

    /* andx32 dst src off */
		else if (IS_OF_TYPE(node_v, andx32)) {
			prog[prog_len++] = BPF_ATOMIC_OP(32, BPF_AND,
				                               get_reg(node_v1), get_reg(node_v2),
																			 (__s16)get_val<int>(node_v3));
		}

    /* andx64 dst src off */
		else if (IS_OF_TYPE(node_v, andx64)) {
			prog[prog_len++] = BPF_ATOMIC_OP(64, BPF_AND,
				                               get_reg(node_v1), get_reg(node_v2),
																			 (__s16)get_val<int>(node_v3));
		}

    /* orx16 dst src off */
		else if (IS_OF_TYPE(node_v, orx16)) {
			prog[prog_len++] = BPF_ATOMIC_OP(16, BPF_OR,
				                               get_reg(node_v1), get_reg(node_v2),
																			 (__s16)get_val<int>(node_v3));
		}

    /* orx32 dst src off */
		else if (IS_OF_TYPE(node_v, orx32)) {
			prog[prog_len++] = BPF_ATOMIC_OP(32, BPF_OR,
				                               get_reg(node_v1), get_reg(node_v2),
																			 (__s16)get_val<int>(node_v3));
		}

    /* orx64 dst src off */
		else if (IS_OF_TYPE(node_v, orx64)) {
			prog[prog_len++] = BPF_ATOMIC_OP(64, BPF_OR,
				                               get_reg(node_v1), get_reg(node_v2),
																			 (__s16)get_val<int>(node_v3));
		}

    /* xorx16 dst src off */
		else if (IS_OF_TYPE(node_v, xorx16)) {
			prog[prog_len++] = BPF_ATOMIC_OP(16, BPF_XOR,
				                               get_reg(node_v1), get_reg(node_v2),
																			 (__s16)get_val<int>(node_v3));
		}

    /* xorx32 dst src off */
		else if (IS_OF_TYPE(node_v, xorx32)) {
			prog[prog_len++] = BPF_ATOMIC_OP(32, BPF_XOR,
				                               get_reg(node_v1), get_reg(node_v2),
																			 (__s16)get_val<int>(node_v3));
		}

    /* xorx64 dst src off */
		else if (IS_OF_TYPE(node_v, xorx64)) {
			prog[prog_len++] = BPF_ATOMIC_OP(64, BPF_XOR,
				                               get_reg(node_v1), get_reg(node_v2),
																			 (__s16)get_val<int>(node_v3));
		}

    /* addfx16 dst src off */
		else if (IS_OF_TYPE(node_v, addfx16)) {
			prog[prog_len++] = BPF_ATOMIC_OP(16, BPF_ADD | BPF_FETCH,
				                               get_reg(node_v1), get_reg(node_v2),
																			 (__s16)get_val<int>(node_v3));
		}

    /* addfx32 dst src off */
		else if (IS_OF_TYPE(node_v, addfx32)) {
			prog[prog_len++] = BPF_ATOMIC_OP(32, BPF_ADD | BPF_FETCH,
				                               get_reg(node_v1), get_reg(node_v2),
																			 (__s16)get_val<int>(node_v3));
		}

    /* addfx64 dst src off */
		else if (IS_OF_TYPE(node_v, addfx64)) {
			prog[prog_len++] = BPF_ATOMIC_OP(64, BPF_ADD | BPF_FETCH,
				                               get_reg(node_v1), get_reg(node_v2),
																			 (__s16)get_val<int>(node_v3));
		}

    /* andfx16 dst src off */
		else if (IS_OF_TYPE(node_v, andfx16)) {
			prog[prog_len++] = BPF_ATOMIC_OP(16, BPF_AND | BPF_FETCH,
				                               get_reg(node_v1), get_reg(node_v2),
																			 (__s16)get_val<int>(node_v3));
		}

    /* andfx32 dst src off */
		else if (IS_OF_TYPE(node_v, andfx32)) {
			prog[prog_len++] = BPF_ATOMIC_OP(32, BPF_AND | BPF_FETCH,
				                               get_reg(node_v1), get_reg(node_v2),
																			 (__s16)get_val<int>(node_v3));
		}

    /* andfx64 dst src off */
		else if (IS_OF_TYPE(node_v, andfx64)) {
			prog[prog_len++] = BPF_ATOMIC_OP(64, BPF_AND | BPF_FETCH,
				                               get_reg(node_v1), get_reg(node_v2),
																			 (__s16)get_val<int>(node_v3));
		}

    /* orfx16 dst src off */
		else if (IS_OF_TYPE(node_v, orfx16)) {
			prog[prog_len++] = BPF_ATOMIC_OP(16, BPF_OR | BPF_FETCH,
				                               get_reg(node_v1), get_reg(node_v2),
																			 (__s16)get_val<int>(node_v3));
		}

    /* orfx32 dst src off */
		else if (IS_OF_TYPE(node_v, orfx32)) {
			prog[prog_len++] = BPF_ATOMIC_OP(32, BPF_OR | BPF_FETCH,
				                               get_reg(node_v1), get_reg(node_v2),
																			 (__s16)get_val<int>(node_v3));
		}

    /* orfx64 dst src off */
		else if (IS_OF_TYPE(node_v, orfx64)) {
			prog[prog_len++] = BPF_ATOMIC_OP(64, BPF_OR | BPF_FETCH,
				                               get_reg(node_v1), get_reg(node_v2),
																			 (__s16)get_val<int>(node_v3));
		}

    /* xorfx16 dst src off */
		else if (IS_OF_TYPE(node_v, xorfx16)) {
			prog[prog_len++] = BPF_ATOMIC_OP(16, BPF_XOR | BPF_FETCH,
				                               get_reg(node_v1), get_reg(node_v2),
																			 (__s16)get_val<int>(node_v3));
		}

    /* xorfx32 dst src off */
		else if (IS_OF_TYPE(node_v, xorfx32)) {
			prog[prog_len++] = BPF_ATOMIC_OP(32, BPF_XOR | BPF_FETCH,
				                               get_reg(node_v1), get_reg(node_v2),
																			 (__s16)get_val<int>(node_v3));
		}

    /* xorfx64 dst src off */
		else if (IS_OF_TYPE(node_v, xorfx64)) {
			prog[prog_len++] = BPF_ATOMIC_OP(64, BPF_XOR | BPF_FETCH,
				                               get_reg(node_v1), get_reg(node_v2),
																			 (__s16)get_val<int>(node_v3));
		}

    /* xchgx16 dst src off */
		else if (IS_OF_TYPE(node_v, xchgx16)) {
			prog[prog_len++] = BPF_ATOMIC_OP(16, BPF_XCHG,
				                               get_reg(node_v1), get_reg(node_v2),
																			 (__s16)get_val<int>(node_v3));
		}

    /* xchgx32 dst src off */
		else if (IS_OF_TYPE(node_v, xchgx32)) {
			prog[prog_len++] = BPF_ATOMIC_OP(32, BPF_XCHG,
				                               get_reg(node_v1), get_reg(node_v2),
																			 (__s16)get_val<int>(node_v3));
		}

    /* xchgx64 dst src off */
		else if (IS_OF_TYPE(node_v, xchgx64)) {
			prog[prog_len++] = BPF_ATOMIC_OP(64, BPF_XCHG,
				                               get_reg(node_v1), get_reg(node_v2),
																			 (__s16)get_val<int>(node_v3));
		}

    /* cmpxchgx16 dst src off */
		else if (IS_OF_TYPE(node_v, cmpxchgx16)) {
			prog[prog_len++] = BPF_ATOMIC_OP(16, BPF_CMPXCHG,
				                               get_reg(node_v1), get_reg(node_v2),
																			 (__s16)get_val<int>(node_v3));
		}

    /* cmpxchgx32 dst src off */
		else if (IS_OF_TYPE(node_v, cmpxchgx32)) {
			prog[prog_len++] = BPF_ATOMIC_OP(32, BPF_CMPXCHG,
				                               get_reg(node_v1), get_reg(node_v2),
																			 (__s16)get_val<int>(node_v3));
		}

    /* cmpxchgx64 dst src off */
		else if (IS_OF_TYPE(node_v, cmpxchgx64)) {
			prog[prog_len++] = BPF_ATOMIC_OP(64, BPF_CMPXCHG,
				                               get_reg(node_v1), get_reg(node_v2),
																			 (__s16)get_val<int>(node_v3));
		}

    /* ldmapfd dst imm */
    else if (IS_OF_TYPE(node_v, ldmapfd)) {
			prog[prog_len++] = BPF_LD_MAP_FD(get_reg(node_v1), get_val<int>(node_v2));
		}

    /* ld64 dst imm */
    else if (IS_OF_TYPE(node_v, ld64)) {
			prog[prog_len++] = BPF_LD_IMM64(get_reg(node_v1), get_val<int>(node_v2));
		}

    /* ldabs8 imm */
		else if (IS_OF_TYPE(node_v, ldabs8)) {
			prog[prog_len++] = BPF_LD_ABS(8, get_val<int>(node_v1));
		}

    /* ldabs16 imm */
		else if (IS_OF_TYPE(node_v, ldabs16)) {
			prog[prog_len++] = BPF_LD_ABS(16, get_val<int>(node_v1));
		}

    /* ldabs32 imm */
		else if (IS_OF_TYPE(node_v, ldabs32)) {
			prog[prog_len++] = BPF_LD_ABS(32, get_val<int>(node_v1));
		}

    /* ldabs64 imm */
		else if (IS_OF_TYPE(node_v, ldabs64)) {
			prog[prog_len++] = BPF_LD_ABS(64, get_val<int>(node_v1));
		}

    /* ldind8 src imm */
		else if (IS_OF_TYPE(node_v, ldind8)) {
			prog[prog_len++] =
			  BPF_LD_IND(8, get_reg(node_v1), get_val<int>(node_v2));
		}

    /* ldind16 src imm */
		else if (IS_OF_TYPE(node_v, ldind16)) {
			prog[prog_len++] =
			  BPF_LD_IND(16, get_reg(node_v1), get_val<int>(node_v2));
		}


    /* ldind32 src imm */
		else if (IS_OF_TYPE(node_v, ldind32)) {
			prog[prog_len++] =
			  BPF_LD_IND(32, get_reg(node_v1), get_val<int>(node_v2));
		}


    /* ldind64 src imm */
		else if (IS_OF_TYPE(node_v, ldind64)) {
			prog[prog_len++] =
			  BPF_LD_IND(64, get_reg(node_v1), get_val<int>(node_v2));
		}


    /* ldx8 dst src off */
		else if (IS_OF_TYPE(node_v, ldx8)) {
			prog[prog_len++] =
			  BPF_LDX_MEM(8, get_reg(node_v1), get_reg(node_v2),
				            (__s16)get_val<int>(node_v3));
		}

    /* ldx16 dst src off */
		else if (IS_OF_TYPE(node_v, ldx16)) {
			prog[prog_len++] =
			  BPF_LDX_MEM(16, get_reg(node_v1), get_reg(node_v2),
				            (__s16)get_val<int>(node_v3));
		}

    /* ldx32 dst src off */
		else if (IS_OF_TYPE(node_v, ldx32)) {
			prog[prog_len++] =
			  BPF_LDX_MEM(32, get_reg(node_v1), get_reg(node_v2),
				            (__s16)get_val<int>(node_v3));
		}

    /* ldx64 dst src off */
		else if (IS_OF_TYPE(node_v, ldx64)) {
			prog[prog_len++] =
			  BPF_LDX_MEM(64, get_reg(node_v1), get_reg(node_v2),
				            (__s16)get_val<int>(node_v3));
		}

    /* st8 dst off imm */
		else if (IS_OF_TYPE(node_v, st8)) {
			prog[prog_len++] =
			  BPF_ST_MEM(8, get_reg(node_v1), (__s16)get_val<int>(node_v2),
				           get_val<int>(node_v2));
		}

    /* st16 dst off imm */
		else if (IS_OF_TYPE(node_v, st16)) {
			prog[prog_len++] =
			  BPF_ST_MEM(16, get_reg(node_v1), (__s16)get_val<int>(node_v2),
				           get_val<int>(node_v2));
		}

    /* st32 dst off imm */
		else if (IS_OF_TYPE(node_v, st32)) {
			prog[prog_len++] =
			  BPF_ST_MEM(32, get_reg(node_v1), (__s16)get_val<int>(node_v2),
				           get_val<int>(node_v2));
		}

    /* st64 dst off imm */
		else if (IS_OF_TYPE(node_v, st64)) {
			prog[prog_len++] =
			  BPF_ST_MEM(64, get_reg(node_v1), (__s16)get_val<int>(node_v2),
				           get_val<int>(node_v2));
		}

    /* stx8 dst src off */
		else if (IS_OF_TYPE(node_v, stx8)) {
			prog[prog_len++] =
			  BPF_STX_MEM(8, get_reg(node_v1), get_reg(node_v2),
				            (__s16)get_val<int>(node_v3));
		}

    /* stx16 dst src off */
		else if (IS_OF_TYPE(node_v, stx16)) {
			prog[prog_len++] =
			  BPF_STX_MEM(16, get_reg(node_v1), get_reg(node_v2),
				            (__s16)get_val<int>(node_v3));
		}

    /* stx32 dst src off */
		else if (IS_OF_TYPE(node_v, stx32)) {
			prog[prog_len++] =
			  BPF_STX_MEM(32, get_reg(node_v1), get_reg(node_v2),
				            (__s16)get_val<int>(node_v3));
		}

    /* stx64 dst src off */
		else if (IS_OF_TYPE(node_v, stx64)) {
			prog[prog_len++] =
			  BPF_STX_MEM(64, get_reg(node_v1), get_reg(node_v2),
				            (__s16)get_val<int>(node_v3));
		}

    /* stxx8 dst src off */
		else if (IS_OF_TYPE(node_v, stxx8)) {
			prog[prog_len++] =
			  BPF_STX_XADD(8, get_reg(node_v1), get_reg(node_v2),
				             (__s16)get_val<int>(node_v3));
		}

    /* stxx16 dst src off */
		else if (IS_OF_TYPE(node_v, stxx16)) {
			prog[prog_len++] =
			  BPF_STX_XADD(16, get_reg(node_v1), get_reg(node_v2),
				             (__s16)get_val<int>(node_v3));
		}

    /* stxx32 dst src off */
		else if (IS_OF_TYPE(node_v, stxx32)) {
			prog[prog_len++] =
			  BPF_STX_XADD(32, get_reg(node_v1), get_reg(node_v2),
				             (__s16)get_val<int>(node_v3));
		}

    /* stxx64 dst src off */
		else if (IS_OF_TYPE(node_v, stxx64)) {
			prog[prog_len++] =
			  BPF_STX_XADD(64, get_reg(node_v1), get_reg(node_v2),
				             (__s16)get_val<int>(node_v3));
		}

		/* Branch instructions: */
		/* 64-bit: */

		/* ja off */
		else if (IS_OF_TYPE(node_v, ja)) {
			prog[prog_len++] = BPF_JMP_A((__s16)get_val<int>(node_v1));
		}

		/* jeq dst src|imm off */
		else if (IS_OF_TYPE(node_v, jeq)) {
			if (IS_OF_TYPE(node_v2, imm_int))
			  prog[prog_len++] =
				   BPF_JMP_IMM(BPF_JEQ, get_reg(node_v1), get_val<int>(node_v2),
					             (__s16)get_val<int>(node_v3));
			else
			  prog[prog_len++] =
				  BPF_JMP_REG(BPF_JEQ, get_reg(node_v1), get_reg(node_v2),
			                (__s16)get_val<int>(node_v3));
		}

    /* jgt dst src|imm off */
		else if (IS_OF_TYPE(node_v, jgt)) {
			if (IS_OF_TYPE(node_v2, imm_int))
			  prog[prog_len++] =
				   BPF_JMP_IMM(BPF_JGT, get_reg(node_v1), get_val<int>(node_v2),
					             (__s16)get_val<int>(node_v3));
			else
			  prog[prog_len++] =
				  BPF_JMP_REG(BPF_JGT, get_reg(node_v1), get_reg(node_v2),
			                (__s16)get_val<int>(node_v3));
		}

    /* jge dst src|imm off */
		else if (IS_OF_TYPE(node_v, jge)) {
			if (IS_OF_TYPE(node_v2, imm_int))
			  prog[prog_len++] =
				   BPF_JMP_IMM(BPF_JGE, get_reg(node_v1), get_val<int>(node_v2),
					             (__s16)get_val<int>(node_v3));
			else
			  prog[prog_len++] =
				  BPF_JMP_REG(BPF_JGE, get_reg(node_v1), get_reg(node_v2),
			                (__s16)get_val<int>(node_v3));
		}

    /* jlt dst src|imm off */
		else if (IS_OF_TYPE(node_v, jlt)) {
			if (IS_OF_TYPE(node_v2, imm_int))
			  prog[prog_len++] =
				   BPF_JMP_IMM(BPF_JLT, get_reg(node_v1), get_val<int>(node_v2),
					             (__s16)get_val<int>(node_v3));
			else
			  prog[prog_len++] =
				  BPF_JMP_REG(BPF_JLT, get_reg(node_v1), get_reg(node_v2),
			                (__s16)get_val<int>(node_v3));
		}

    /* jle dst src|imm off */
		else if (IS_OF_TYPE(node_v, jle)) {
			if (IS_OF_TYPE(node_v2, imm_int))
			  prog[prog_len++] =
				   BPF_JMP_IMM(BPF_JLE, get_reg(node_v1), get_val<int>(node_v2),
					             (__s16)get_val<int>(node_v3));
			else
			  prog[prog_len++] =
				  BPF_JMP_REG(BPF_JLE, get_reg(node_v1), get_reg(node_v2),
			                (__s16)get_val<int>(node_v3));
		}

    /* jset dst src|imm off */
		else if (IS_OF_TYPE(node_v, jset)) {
			if (IS_OF_TYPE(node_v2, imm_int))
			  prog[prog_len++] =
				   BPF_JMP_IMM(BPF_JSET, get_reg(node_v1), get_val<int>(node_v2),
					             (__s16)get_val<int>(node_v3));
			else
			  prog[prog_len++] =
				  BPF_JMP_REG(BPF_JSET, get_reg(node_v1), get_reg(node_v2),
			                (__s16)get_val<int>(node_v3));
		}

    /* jne dst src|imm off */
		else if (IS_OF_TYPE(node_v, jne)) {
			if (IS_OF_TYPE(node_v2, imm_int))
			  prog[prog_len++] =
				   BPF_JMP_IMM(BPF_JNE, get_reg(node_v1), get_val<int>(node_v2),
					             (__s16)get_val<int>(node_v3));
			else
			  prog[prog_len++] =
				  BPF_JMP_REG(BPF_JNE, get_reg(node_v1), get_reg(node_v2),
			                (__s16)get_val<int>(node_v3));
		}

    /* jsgt dst src|imm off */
		else if (IS_OF_TYPE(node_v, jsgt)) {
			if (IS_OF_TYPE(node_v2, imm_int))
			  prog[prog_len++] =
				   BPF_JMP_IMM(BPF_JSGT, get_reg(node_v1), get_val<int>(node_v2),
					             (__s16)get_val<int>(node_v3));
			else
			  prog[prog_len++] =
				  BPF_JMP_REG(BPF_JSGT, get_reg(node_v1), get_reg(node_v2),
			                (__s16)get_val<int>(node_v3));
		}

    /* jsge dst src|imm off */
		else if (IS_OF_TYPE(node_v, jsge)) {
			if (IS_OF_TYPE(node_v2, imm_int))
			  prog[prog_len++] =
				   BPF_JMP_IMM(BPF_JSGE, get_reg(node_v1), get_val<int>(node_v2),
					             (__s16)get_val<int>(node_v3));
			else
			  prog[prog_len++] =
				  BPF_JMP_REG(BPF_JSGE, get_reg(node_v1), get_reg(node_v2),
			                (__s16)get_val<int>(node_v3));
		}

    /* jslt dst src|imm off */
		else if (IS_OF_TYPE(node_v, jslt)) {
			if (IS_OF_TYPE(node_v2, imm_int))
			  prog[prog_len++] =
				   BPF_JMP_IMM(BPF_JSLT, get_reg(node_v1), get_val<int>(node_v2),
					             (__s16)get_val<int>(node_v3));
			else
			  prog[prog_len++] =
				  BPF_JMP_REG(BPF_JSLT, get_reg(node_v1), get_reg(node_v2),
			                (__s16)get_val<int>(node_v3));
		}

    /* jsle dst src|imm off */
		else if (IS_OF_TYPE(node_v, jsle)) {
			if (IS_OF_TYPE(node_v2, imm_int))
			  prog[prog_len++] =
				   BPF_JMP_IMM(BPF_JSLE, get_reg(node_v1), get_val<int>(node_v2),
					             (__s16)get_val<int>(node_v3));
			else
			  prog[prog_len++] =
				  BPF_JMP_REG(BPF_JSLE, get_reg(node_v1), get_reg(node_v2),
			                (__s16)get_val<int>(node_v3));
		}

    /* call imm */
	  else if (IS_OF_TYPE(node_v, call)) {
			error("error: call: instruction not yet supported.");
		}

    /* rel imm */
	  else if (IS_OF_TYPE(node_v, rel)) {
			prog[prog_len++] = BPF_CALL_REL(get_val<int>(node_v1));
		}

	  /* exit */
	  else if (IS_OF_TYPE(node_v, exit_ins)) {
			prog[prog_len++] = BPF_EXIT_INSN();
		}

		/* 32-bit: */

		/* jeq32 dst src|imm off */
		else if (IS_OF_TYPE(node_v, jeq32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
			  prog[prog_len++] =
				   BPF_JMP32_IMM(BPF_JEQ, get_reg(node_v1), get_val<int>(node_v2),
					             (__s16)get_val<int>(node_v3));
			else
			  prog[prog_len++] =
				  BPF_JMP32_REG(BPF_JEQ, get_reg(node_v1), get_reg(node_v2),
			                (__s16)get_val<int>(node_v3));
		}

    /* jgt32 dst src|imm off */
		else if (IS_OF_TYPE(node_v, jgt32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
			  prog[prog_len++] =
				   BPF_JMP32_IMM(BPF_JGT, get_reg(node_v1), get_val<int>(node_v2),
					             (__s16)get_val<int>(node_v3));
			else
			  prog[prog_len++] =
				  BPF_JMP32_REG(BPF_JGT, get_reg(node_v1), get_reg(node_v2),
			                (__s16)get_val<int>(node_v3));
		}

    /* jge32 dst src|imm off */
		else if (IS_OF_TYPE(node_v, jge32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
			  prog[prog_len++] =
				   BPF_JMP32_IMM(BPF_JGE, get_reg(node_v1), get_val<int>(node_v2),
					             (__s16)get_val<int>(node_v3));
			else
			  prog[prog_len++] =
				  BPF_JMP32_REG(BPF_JGE, get_reg(node_v1), get_reg(node_v2),
			                (__s16)get_val<int>(node_v3));
		}

    /* jlt32 dst src|imm off */
		else if (IS_OF_TYPE(node_v, jlt32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
			  prog[prog_len++] =
				   BPF_JMP32_IMM(BPF_JLT, get_reg(node_v1), get_val<int>(node_v2),
					             (__s16)get_val<int>(node_v3));
			else
			  prog[prog_len++] =
				  BPF_JMP32_REG(BPF_JLT, get_reg(node_v1), get_reg(node_v2),
			                (__s16)get_val<int>(node_v3));
		}

    /* jle32 dst src|imm off */
		else if (IS_OF_TYPE(node_v, jle32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
			  prog[prog_len++] =
				   BPF_JMP32_IMM(BPF_JLE, get_reg(node_v1), get_val<int>(node_v2),
					             (__s16)get_val<int>(node_v3));
			else
			  prog[prog_len++] =
				  BPF_JMP32_REG(BPF_JLE, get_reg(node_v1), get_reg(node_v2),
			                (__s16)get_val<int>(node_v3));
		}

    /* jset32 dst src|imm off */
		else if (IS_OF_TYPE(node_v, jset32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
			  prog[prog_len++] =
				   BPF_JMP32_IMM(BPF_JSET, get_reg(node_v1), get_val<int>(node_v2),
					             (__s16)get_val<int>(node_v3));
			else
			  prog[prog_len++] =
				  BPF_JMP32_REG(BPF_JSET, get_reg(node_v1), get_reg(node_v2),
			                (__s16)get_val<int>(node_v3));
		}

    /* jne32 dst src|imm off */
		else if (IS_OF_TYPE(node_v, jne32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
			  prog[prog_len++] =
				   BPF_JMP32_IMM(BPF_JNE, get_reg(node_v1), get_val<int>(node_v2),
					             (__s16)get_val<int>(node_v3));
			else
			  prog[prog_len++] =
				  BPF_JMP32_REG(BPF_JNE, get_reg(node_v1), get_reg(node_v2),
			                (__s16)get_val<int>(node_v3));
		}

    /* jsgt32 dst src|imm off */
		else if (IS_OF_TYPE(node_v, jsgt32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
			  prog[prog_len++] =
				   BPF_JMP32_IMM(BPF_JSGT, get_reg(node_v1), get_val<int>(node_v2),
					             (__s16)get_val<int>(node_v3));
			else
			  prog[prog_len++] =
				  BPF_JMP32_REG(BPF_JSGT, get_reg(node_v1), get_reg(node_v2),
			                (__s16)get_val<int>(node_v3));
		}

    /* jsge32 dst src|imm off */
		else if (IS_OF_TYPE(node_v, jsge32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
			  prog[prog_len++] =
				   BPF_JMP32_IMM(BPF_JSGE, get_reg(node_v1), get_val<int>(node_v2),
					             (__s16)get_val<int>(node_v3));
			else
			  prog[prog_len++] =
				  BPF_JMP32_REG(BPF_JSGE, get_reg(node_v1), get_reg(node_v2),
			                (__s16)get_val<int>(node_v3));
		}

    /* jslt32 dst src|imm off */
		else if (IS_OF_TYPE(node_v, jslt32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
			  prog[prog_len++] =
				   BPF_JMP32_IMM(BPF_JSLT, get_reg(node_v1), get_val<int>(node_v2),
					             (__s16)get_val<int>(node_v3));
			else
			  prog[prog_len++] =
				  BPF_JMP32_REG(BPF_JSLT, get_reg(node_v1), get_reg(node_v2),
			                (__s16)get_val<int>(node_v3));
		}

    /* jsle32 dst src|imm off */
		else if (IS_OF_TYPE(node_v, jsle32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
			  prog[prog_len++] =
				   BPF_JMP32_IMM(BPF_JSLE, get_reg(node_v1), get_val<int>(node_v2),
					             (__s16)get_val<int>(node_v3));
			else
			  prog[prog_len++] =
				  BPF_JMP32_REG(BPF_JSLE, get_reg(node_v1), get_reg(node_v2),
			                (__s16)get_val<int>(node_v3));
		}

		else if (IS_OF_TYPE(node_v, zext)) {
			prog[prog_len++] = BPF_ZEXT_REG(get_reg(node_v1));
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
	std::any node_v, node_v1, node_v2, node_v3;
  Symbol type;
	std::string c_code;

	if (struct_name.size())
		c_code += HEAD_FST_CSTRUCT + struct_name + HEAD_SND_CSTRUCT;
	else
		c_code += HEAD_CSTRUCT;

	size = absyn_tree.size();

	for (i=0; i<size; i++) {
		node   = absyn_tree[i];
		node_v = node.node_v;
		type   = node.type;

  	if (type == instr)
  		ops = get_ops(node_v);
  	else
  		ops = 0;

  	if (ops == 1) {
  		node_v1 = absyn_tree[i+1].node_v;
  	}
  	else if (ops == 2) {
  		node_v1 = absyn_tree[i+1].node_v;
  		node_v2 = absyn_tree[i+2].node_v;
  	}
  	else if (ops == 3) {
  		node_v1 = absyn_tree[i+1].node_v;
  		node_v2 = absyn_tree[i+2].node_v;
  		node_v3 = absyn_tree[i+3].node_v;
  	}

		/* ALU instructions: */
		/* 64-bit: */
		/* add dst src|imm */
		if (IS_OF_TYPE(node_v, add)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_ALU64_IMM(BPF_ADD, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + "),\n";
		  else
		 	  c_code += "BPF_ALU64_REG(BPF_ADD, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + "),\n";
    }

		/* sub dst src|imm */
		else if (IS_OF_TYPE(node_v, sub)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_ALU64_IMM(BPF_SUB, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + "),\n";
		  else
		 	  c_code += "BPF_ALU64_REG(BPF_SUB, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + "),\n";
    }

		/* mul dst src|imm */
		else if (IS_OF_TYPE(node_v, mul)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_ALU64_IMM(BPF_MUL, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + "),\n";
		  else
		 	  c_code += "BPF_ALU64_REG(BPF_MUL, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + "),\n";
    }

		/* div dst src|imm */
		else if (IS_OF_TYPE(node_v, div_ins)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_ALU64_IMM(BPF_DIV, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + "),\n";
		  else
		 	  c_code += "BPF_ALU64_REG(BPF_DIV, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + "),\n";
    }

		/* or dst src|imm */
		else if (IS_OF_TYPE(node_v, or_ins)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_ALU64_IMM(BPF_OR, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + "),\n";
		  else
		 	  c_code += "BPF_ALU64_REG(BPF_OR, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + "),\n";
    }

		/* and dst src|imm */
		else if (IS_OF_TYPE(node_v, and_ins)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_ALU64_IMM(BPF_AND, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + "),\n";
		  else
		 	  c_code += "BPF_ALU64_REG(BPF_AND, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + "),\n";
    }

		/* lsh dst src|imm */
		else if (IS_OF_TYPE(node_v, lsh)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_ALU64_IMM(BPF_LSH, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + "),\n";
		  else
		 	  c_code += "BPF_ALU64_REG(BPF_LSH, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + "),\n";
    }

		/* rsh dst src|imm */
		else if (IS_OF_TYPE(node_v, rsh)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_ALU64_IMM(BPF_RSH, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + "),\n";
		  else
		 	  c_code += "BPF_ALU64_REG(BPF_RSH, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + "),\n";
    }

		/* neg dst src|imm */
		else if (IS_OF_TYPE(node_v, neg)) {
		 	c_code += "BPF_ALU64_REG(BPF_NEG, " + get_reg_str(node_v1) + ", 0),\n";
    }

		/* mod dst src|imm */
		else if (IS_OF_TYPE(node_v, mod)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_ALU64_IMM(BPF_MOD, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + "),\n";
		  else
		 	  c_code += "BPF_ALU64_REG(BPF_MOD, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + "),\n";
    }

		/* xor dst src|imm */
		else if (IS_OF_TYPE(node_v, xor_ins)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_ALU64_IMM(BPF_XOR, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + "),\n";
		  else
		 	  c_code += "BPF_ALU64_REG(BPF_XOR, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + "),\n";
    }

		/* mov dst src|imm */
    else if (IS_OF_TYPE(node_v, mov)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_ALU64_IMM(BPF_MOV, " + get_reg_str(node_v1) + ", " +
									 std::to_string(get_val<int>(node_v2)) + "),\n";
			else
				c_code += "BPF_ALU64_REG(BPF_MOV, " + get_reg_str(node_v1) + ", " +
									get_reg_str(node_v2) + "),\n";
		 }

		/* arsh dst src|imm */
		else if (IS_OF_TYPE(node_v, arsh)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_ALU64_IMM(BPF_ARSH, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + "),\n";
		  else
		 	  c_code += "BPF_ALU64_REG(BPF_ARSH, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + "),\n";
    }

		/* 32-bit: */
		/* add32 dst src|imm */
		if (IS_OF_TYPE(node_v, add32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_ALU32_IMM(BPF_ADD, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + "),\n";
		  else
		 	  c_code += "BPF_ALU32_REG(BPF_ADD, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + "),\n";
    }

		/* sub32 dst src|imm */
		else if (IS_OF_TYPE(node_v, sub32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_ALU32_IMM(BPF_SUB, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + "),\n";
		  else
		 	  c_code += "BPF_ALU32_REG(BPF_SUB, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + "),\n";
    }

		/* mul32 dst src|imm */
		else if (IS_OF_TYPE(node_v, mul32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_ALU32_IMM(BPF_MUL, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + "),\n";
		  else
		 	  c_code += "BPF_ALU32_REG(BPF_MUL, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + "),\n";
    }

		/* div32 dst src|imm */
		else if (IS_OF_TYPE(node_v, div32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_ALU32_IMM(BPF_DIV, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + "),\n";
		  else
		 	  c_code += "BPF_ALU32_REG(BPF_DIV, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + "),\n";
    }

		/* or32 dst src|imm */
		else if (IS_OF_TYPE(node_v, or32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_ALU32_IMM(BPF_OR, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + "),\n";
		  else
		 	  c_code += "BPF_ALU32_REG(BPF_OR, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + "),\n";
    }

		/* and32 dst src|imm */
		else if (IS_OF_TYPE(node_v, and32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_ALU32_IMM(BPF_AND, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + "),\n";
		  else
		 	  c_code += "BPF_ALU32_REG(BPF_AND, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + "),\n";
    }

		/* lsh32 dst src|imm */
		else if (IS_OF_TYPE(node_v, lsh32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_ALU32_IMM(BPF_LSH, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + "),\n";
		  else
		 	  c_code += "BPF_ALU32_REG(BPF_LSH, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + "),\n";
    }

		/* rsh32 dst src|imm */
		else if (IS_OF_TYPE(node_v, rsh32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_ALU32_IMM(BPF_RSH, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + "),\n";
		  else
		 	  c_code += "BPF_ALU32_REG(BPF_RSH, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + "),\n";
    }

		/* neg32 dst src|imm */
		else if (IS_OF_TYPE(node_v, neg32)) {
		 	c_code += "BPF_ALU32_REG(BPF_NEG, " + get_reg_str(node_v1) + ", 0),\n";
    }

		/* mod32 dst src|imm */
		else if (IS_OF_TYPE(node_v, mod32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_ALU32_IMM(BPF_MOD, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + "),\n";
		  else
		 	  c_code += "BPF_ALU32_REG(BPF_MOD, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + "),\n";
    }

		/* xor32 dst src|imm */
		else if (IS_OF_TYPE(node_v, xor32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_ALU32_IMM(BPF_XOR, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + "),\n";
		  else
		 	  c_code += "BPF_ALU32_REG(BPF_XOR, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + "),\n";
    }

		/* mov32 dst src|imm */
    else if (IS_OF_TYPE(node_v, mov32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_ALU32_IMM(BPF_MOV, " + get_reg_str(node_v1) + ", " +
									 std::to_string(get_val<int>(node_v2)) + "),\n";
			else
				c_code += "BPF_ALU32_REG(BPF_MOV, " + get_reg_str(node_v1) + ", " +
									get_reg_str(node_v2) + "),\n";
		 }

		/* arsh32 dst src|imm */
		else if (IS_OF_TYPE(node_v, arsh32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_ALU32_IMM(BPF_ARSH, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + "),\n";
		  else
		 	  c_code += "BPF_ALU32_REG(BPF_ARSH, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + "),\n";
    }

		/* le16 dst src|imm */
		else if (IS_OF_TYPE(node_v, le16)) {
		 	c_code += "BPF_ENDIAN(BPF_TO_LE, " + get_reg_str(node_v1) + ", 16),\n";
    }

		/* le32 dst src|imm */
		else if (IS_OF_TYPE(node_v, le32)) {
		 	c_code += "BPF_ENDIAN(BPF_TO_LE, " + get_reg_str(node_v1) + ", 32),\n";
    }

		/* le64 dst src|imm */
		else if (IS_OF_TYPE(node_v, le64)) {
		 	c_code += "BPF_ENDIAN(BPF_TO_LE, " + get_reg_str(node_v1) + ", 64),\n";
    }

		/* be16 dst src|imm */
		else if (IS_OF_TYPE(node_v, be16)) {
		 	c_code += "BPF_ENDIAN(BPF_TO_BE, " + get_reg_str(node_v1) + ", 16),\n";
    }

		/* be32 dst src|imm */
		else if (IS_OF_TYPE(node_v, be32)) {
		 	c_code += "BPF_ENDIAN(BPF_TO_BE, " + get_reg_str(node_v1) + ", 32),\n";
    }

		/* be64 dst src|imm */
		else if (IS_OF_TYPE(node_v, be64)) {
		 	c_code += "BPF_ENDIAN(BPF_TO_BE, " + get_reg_str(node_v1) + ", 64),\n";
    }

		/* addx16 dst src off */
		else if (IS_OF_TYPE(node_v, addx16)) {
		 	c_code += "BPF_ATOMIC_OP(16, BPF_ADD, " + get_reg_str(node_v1) + ", " +
			          get_reg_str(node_v2) + ", " +
								std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* addx32 dst src off */
		else if (IS_OF_TYPE(node_v, addx32)) {
		 	c_code += "BPF_ATOMIC_OP(32, BPF_ADD, " + get_reg_str(node_v1) + ", " +
			          get_reg_str(node_v2) + ", " +
			          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* addx64 dst src off */
		else if (IS_OF_TYPE(node_v, addx64)) {
		 	c_code += "BPF_ATOMIC_OP(64, BPF_ADD, " + get_reg_str(node_v1) + ", " +
			          get_reg_str(node_v2) + ", " +
			          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* andx16 dst src off */
		else if (IS_OF_TYPE(node_v, andx16)) {
		 	c_code += "BPF_ATOMIC_OP(16, BPF_AND, " + get_reg_str(node_v1) + ", " +
			           get_reg_str(node_v2) + ", " +
			           std::to_string((__s16)get_val<int>(node_v3))	+ "),\n";
    }

		/* andx32 dst src off */
		else if (IS_OF_TYPE(node_v, andx32)) {
		 	c_code += "BPF_ATOMIC_OP(32, BPF_AND, " + get_reg_str(node_v1) + ", " +
			          get_reg_str(node_v2) + ", " +
								std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* andx64 dst src off */
		else if (IS_OF_TYPE(node_v, andx64)) {
		 	c_code += "BPF_ATOMIC_OP(64, BPF_AND, " + get_reg_str(node_v1) + ", " +
			get_reg_str(node_v2) + ", " +
			std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* orx16 dst src off */
		else if (IS_OF_TYPE(node_v, orx16)) {
		 	c_code += "BPF_ATOMIC_OP(16, BPF_OR, " + get_reg_str(node_v1) + ", " +
			           get_reg_str(node_v2) + ", " +
			           std::to_string((__s16)get_val<int>(node_v3))	+ "),\n";
    }

		/* orx32 dst src off */
		else if (IS_OF_TYPE(node_v, orx32)) {
		 	c_code += "BPF_ATOMIC_OP(32, BPF_OR, " + get_reg_str(node_v1) + ", " +
			           get_reg_str(node_v2) + ", " +
			           std::to_string((__s16)get_val<int>(node_v3))	+ "),\n";
    }

		/* orx64 dst src off */
		else if (IS_OF_TYPE(node_v, orx64)) {
		 	c_code += "BPF_ATOMIC_OP(64, BPF_OR, " + get_reg_str(node_v1) + ", " +
			           get_reg_str(node_v2) + ", " +
			           std::to_string((__s16)get_val<int>(node_v3))	+ "),\n";
    }

		/* xorx16 dst src off */
		else if (IS_OF_TYPE(node_v, xorx16)) {
		 	c_code += "BPF_ATOMIC_OP(16, BPF_XOR, " + get_reg_str(node_v1) + ", " +
			           get_reg_str(node_v2) + ", " +
			           std::to_string((__s16)get_val<int>(node_v3))	+ "),\n";
    }

		/* xorx32 dst src off */
		else if (IS_OF_TYPE(node_v, xorx32)) {
		 	c_code += "BPF_ATOMIC_OP(32, BPF_XOR, " + get_reg_str(node_v1) + ", " +
			          get_reg_str(node_v2) + ", " +
			          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* xorx64 dst src off */
		else if (IS_OF_TYPE(node_v, xorx64)) {
		 	c_code += "BPF_ATOMIC_OP(64, BPF_XOR, " + get_reg_str(node_v1) + ", " +
			          get_reg_str(node_v2) + ", " +
			          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* addfx16 dst src off */
		else if (IS_OF_TYPE(node_v, addfx16)) {
		 	c_code += "BPF_ATOMIC_OP(16, BPF_ADD | BPF_FETCH, " +
			get_reg_str(node_v1) + ", " + get_reg_str(node_v2) + ", " +
			std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* addfx32 dst src off */
		else if (IS_OF_TYPE(node_v, addfx32)) {
		 	c_code += "BPF_ATOMIC_OP(32, BPF_ADD | BPF_FETCH, " +
			get_reg_str(node_v1) + ", " + get_reg_str(node_v2) + ", " +
			std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* addfx64 dst src off */
		else if (IS_OF_TYPE(node_v, addfx64)) {
		 	c_code += "BPF_ATOMIC_OP(64, BPF_ADD | BPF_FETCH, " +
			get_reg_str(node_v1) + ", " + get_reg_str(node_v2) + ", " +
			std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* andfx16 dst src off */
		else if (IS_OF_TYPE(node_v, andfx16)) {
		 	c_code += "BPF_ATOMIC_OP(16, BPF_AND | BPF_FETCH, " +
			get_reg_str(node_v1) + ", " + get_reg_str(node_v2) + ", " +
			std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* andfx32 dst src off */
		else if (IS_OF_TYPE(node_v, andfx32)) {
		 	c_code += "BPF_ATOMIC_OP(32, BPF_AND | BPF_FETCH, " +
			get_reg_str(node_v1) + ", " + get_reg_str(node_v2) + ", " +
			std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* andfx64 dst src off */
		else if (IS_OF_TYPE(node_v, andfx64)) {
		 	c_code += "BPF_ATOMIC_OP(64, BPF_AND | BPF_FETCH, " +
			get_reg_str(node_v1) + ", " + get_reg_str(node_v2) + ", " +
			std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* orfx16 dst src off */
		else if (IS_OF_TYPE(node_v, orfx16)) {
		 	c_code += "BPF_ATOMIC_OP(16, BPF_OR | BPF_FETCH, " +
			          get_reg_str(node_v1) + ", " +	get_reg_str(node_v2) + ", " +
								std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* orfx32 dst src off */
		else if (IS_OF_TYPE(node_v, orfx32)) {
		 	c_code += "BPF_ATOMIC_OP(32, BPF_OR | BPF_FETCH, " +
			          get_reg_str(node_v1) + ", " +	get_reg_str(node_v2) + ", " +
								std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* orfx64 dst src off */
		else if (IS_OF_TYPE(node_v, orfx64)) {
		 	c_code += "BPF_ATOMIC_OP(64, BPF_OR | BPF_FETCH, " +
			          get_reg_str(node_v1) + ", " +	get_reg_str(node_v2) + ", " +
								std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* xorfx16 dst src off */
		else if (IS_OF_TYPE(node_v, xorfx16)) {
		 	c_code += "BPF_ATOMIC_OP(16, BPF_XOR | BPF_FETCH, " +
			          get_reg_str(node_v1) + ", " +	get_reg_str(node_v2) + ", " +
								std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* xorfx32 dst src off */
		else if (IS_OF_TYPE(node_v, xorfx32)) {
		 	c_code += "BPF_ATOMIC_OP(32, BPF_XOR | BPF_FETCH, " +
			          get_reg_str(node_v1) + ", " +	get_reg_str(node_v2) + ", " +
								std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* xorfx64 dst src off */
		else if (IS_OF_TYPE(node_v, xorfx64)) {
		 	c_code += "BPF_ATOMIC_OP(64, BPF_XOR | BPF_FETCH, " +
			          get_reg_str(node_v1) + ", " +	get_reg_str(node_v2) + ", " +
								std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* xchgx16 dst src off */
		else if (IS_OF_TYPE(node_v, xchgx16)) {
		 	c_code += "BPF_ATOMIC_OP(16, BPF_XCHG, " + get_reg_str(node_v1) + ", " +
			          get_reg_str(node_v2) + ", " +
								std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* xchgx32 dst src off */
		else if (IS_OF_TYPE(node_v, xchgx32)) {
		 	c_code += "BPF_ATOMIC_OP(32, BPF_XCHG, " + get_reg_str(node_v1) + ", " +
			          get_reg_str(node_v2) + ", " +
								std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* xchgx64 dst src off */
		else if (IS_OF_TYPE(node_v, xchgx64)) {
		 	c_code += "BPF_ATOMIC_OP(64, BPF_XCHG, " + get_reg_str(node_v1) + ", " +
           			get_reg_str(node_v2) + ", " +
								std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* cmpxchgx16 dst src off */
		else if (IS_OF_TYPE(node_v, cmpxchgx16)) {
		 	c_code += "BPF_ATOMIC_OP(16, BPF_CMPXCHG, " + get_reg_str(node_v1) + ", "
			           + get_reg_str(node_v2) + ", " +
			           std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* cmpxchgx32 dst src off */
		else if (IS_OF_TYPE(node_v, cmpxchgx32)) {
		 	c_code += "BPF_ATOMIC_OP(32, BPF_CMPXCHG, " + get_reg_str(node_v1) + ", "
			          + get_reg_str(node_v2) + ", " +
			          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* cmpxchgx64 dst src off */
		else if (IS_OF_TYPE(node_v, cmpxchgx64)) {
		 	c_code += "BPF_ATOMIC_OP(64, BPF_CMPXCHG, " + get_reg_str(node_v1) + ", "
			          + get_reg_str(node_v2) + ", " +
			          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* ldmapfd dst imm  */
		else if (IS_OF_TYPE(node_v, ldmapfd)) {
		 	c_code += "BPF_LD_MAP_FD(" + get_reg_str(node_v1) + ", " +
			          std::to_string(get_val<int>(node_v2)) + "),\n";
    }

		/* ld64 dst imm  */
		else if (IS_OF_TYPE(node_v, ld64)) {
		 	c_code += "BPF_LD_IMM64(" + get_reg_str(node_v1) + ", " +
			          std::to_string(get_val<int>(node_v2)) + "),\n";
    }

		/* ldabs8 imm  */
		else if (IS_OF_TYPE(node_v, ldabs8)) {
		 	c_code += "BPF_LD_ABS(8, " + std::to_string(get_val<int>(node_v1))
			           + "),\n";
    }

		/* ldabs16 imm  */
		else if (IS_OF_TYPE(node_v, ldabs16)) {
		 	c_code += "BPF_LD_ABS(16, " + std::to_string(get_val<int>(node_v1))
			           + "),\n";
    }

		/* ldabs32 imm  */
		else if (IS_OF_TYPE(node_v, ldabs32)) {
		 	c_code += "BPF_LD_ABS(32, " + std::to_string(get_val<int>(node_v1))
			           + "),\n";
    }

		/* ldabs64 imm  */
		else if (IS_OF_TYPE(node_v, ldabs64)) {
		 	c_code += "BPF_LD_ABS(64, " + std::to_string(get_val<int>(node_v1))
			           + "),\n";
    }

		/* ldind8 src imm  */
		else if (IS_OF_TYPE(node_v, ldind8)) {
		 	c_code += "BPF_LD_IND(8, " + get_reg_str(node_v1) + ", " +
			          std::to_string(get_val<int>(node_v2)) + "),\n";
    }

		/* ldind16 src imm  */
		else if (IS_OF_TYPE(node_v, ldind16)) {
		 	c_code += "BPF_LD_IND(16, " + get_reg_str(node_v1) + ", " +
			          std::to_string(get_val<int>(node_v2)) + "),\n";
    }

		/* ldind32 src imm  */
		else if (IS_OF_TYPE(node_v, ldind32)) {
		 	c_code += "BPF_LD_IND(32, " + get_reg_str(node_v1) + ", " +
			          std::to_string(get_val<int>(node_v2)) + "),\n";
    }

		/* ldind64 src imm  */
		else if (IS_OF_TYPE(node_v, ldind64)) {
		 	c_code += "BPF_LD_IND(64, " + get_reg_str(node_v1) + ", " +
			          std::to_string(get_val<int>(node_v2)) + "),\n";
    }

		/* ldx8 dst src off  */
		else if (IS_OF_TYPE(node_v, ldx8)) {
		 	c_code += "BPF_LDX_MEM(8, " + get_reg_str(node_v1) + ", " +
			          get_reg_str(node_v2) + ", " +
			          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* ldx16 dst src off  */
		else if (IS_OF_TYPE(node_v, ldx16)) {
		 	c_code += "BPF_LDX_MEM(16, " + get_reg_str(node_v1) + ", " +
			          get_reg_str(node_v2) + ", " +
			          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* ldx32 dst src off  */
		else if (IS_OF_TYPE(node_v, ldx32)) {
		 	c_code += "BPF_LDX_MEM(32, " + get_reg_str(node_v1) + ", " +
			          get_reg_str(node_v2) + ", " +
			          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* ldx64 dst src off  */
		else if (IS_OF_TYPE(node_v, ldx64)) {
		 	c_code += "BPF_LDX_MEM(64, " + get_reg_str(node_v1) + ", " +
			          get_reg_str(node_v2) + ", " +
			          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* st8 dst off imm  */
		else if (IS_OF_TYPE(node_v, st8)) {
		 	c_code += "BPF_ST_MEM(8, " + get_reg_str(node_v1) + ", " +
			          std::to_string((__s16)get_val<int>(node_v2)) + ", " +
			          std::to_string(get_val<int>(node_v3)) + "),\n";
    }

		/* st16 dst off imm   */
		else if (IS_OF_TYPE(node_v, st16)) {
		 	c_code += "BPF_ST_MEM(16, " + get_reg_str(node_v1) + ", " +
			          std::to_string((__s16)get_val<int>(node_v2)) + ", " +
			          std::to_string(get_val<int>(node_v3)) + "),\n";
    }

		/* st32 dst off imm   */
		else if (IS_OF_TYPE(node_v, st32)) {
		 	c_code += "BPF_ST_MEM(32, " + get_reg_str(node_v1) + ", " +
			          std::to_string((__s16)get_val<int>(node_v2)) + ", " +
			          std::to_string(get_val<int>(node_v3)) + "),\n";
    }

		/* st64 dst off imm   */
		else if (IS_OF_TYPE(node_v, st64)) {
		 	c_code += "BPF_ST_MEM(64, " + get_reg_str(node_v1) + ", " +
			          std::to_string((__s16)get_val<int>(node_v2)) + ", " +
			          std::to_string(get_val<int>(node_v3)) + "),\n";
    }

		/* stx8 dst src off  */
		else if (IS_OF_TYPE(node_v, stx8)) {
		 	c_code += "BPF_STX_MEM(8, " + get_reg_str(node_v1) + ", " +
			          get_reg_str(node_v2) + ", " +
			          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* stx16 dst src off  */
		else if (IS_OF_TYPE(node_v, stx16)) {
		 	c_code += "BPF_STX_MEM(16, " + get_reg_str(node_v1) + ", " +
			          get_reg_str(node_v2) + ", " +
			          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* stx32 dst src off  */
		else if (IS_OF_TYPE(node_v, stx32)) {
		 	c_code += "BPF_STX_MEM(32, " + get_reg_str(node_v1) + ", " +
			          get_reg_str(node_v2) + ", " +
			          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* stx64 dst src off  */
		else if (IS_OF_TYPE(node_v, stx64)) {
		 	c_code += "BPF_STX_MEM(64, " + get_reg_str(node_v1) + ", " +
			          get_reg_str(node_v2) + ", " +
			          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* stxx8 dst src off  */
		else if (IS_OF_TYPE(node_v, stxx8)) {
		 	c_code += "BPF_STX_XADD(8, " + get_reg_str(node_v1) + ", " +
			          get_reg_str(node_v2) + ", " +
			          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* stxx16 dst src off  */
		else if (IS_OF_TYPE(node_v, stxx16)) {
		 	c_code += "BPF_STX_XADD(16, " + get_reg_str(node_v1) + ", " +
			          get_reg_str(node_v2) + ", " +
			          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* stxx32 dst src off  */
		else if (IS_OF_TYPE(node_v, stxx32)) {
		 	c_code += "BPF_STX_XADD(32, " + get_reg_str(node_v1) + ", " +
			          get_reg_str(node_v2) + ", " +
			          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* stxx64 dst src off  */
		else if (IS_OF_TYPE(node_v, stxx64)) {
		 	c_code += "BPF_STX_XADD(64, " + get_reg_str(node_v1) + ", " +
			          get_reg_str(node_v2) + ", " +
			          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* ja off */
		else if (IS_OF_TYPE(node_v, ja)) {
		 	c_code += "BPF_JMP_A(" + std::to_string((__s16)get_val<int>(node_v3))
			          + "),\n";
    }

		/* jeq dst src|imm off */
		else if (IS_OF_TYPE(node_v, jeq)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_JMP_IMM(BPF_JEQ, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + ", " +
				          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
		  else
		 	  c_code += "BPF_JMP_REG(BPF_JEQ, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + ", " +
									std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* jgt dst src|imm off */
		else if (IS_OF_TYPE(node_v, jgt)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_JMP_IMM(BPF_JGT, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + ", " +
				          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
		  else
		 	  c_code += "BPF_JMP_REG(BPF_JGT, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + ", " +
									std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* jge dst src|imm off */
		else if (IS_OF_TYPE(node_v, jge)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_JMP_IMM(BPF_JGE, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + ", " +
				          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
		  else
		 	  c_code += "BPF_JMP_REG(BPF_JGE, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + ", " +
									std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* jlt dst src|imm off */
		else if (IS_OF_TYPE(node_v, jlt)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_JMP_IMM(BPF_JLT, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + ", " +
				          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
		  else
		 	  c_code += "BPF_JMP_REG(BPF_JLT, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + ", " +
									std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* jle dst src|imm off */
		else if (IS_OF_TYPE(node_v, jle)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_JMP_IMM(BPF_JLE, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + ", " +
				          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
		  else
		 	  c_code += "BPF_JMP_REG(BPF_JLE, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + ", " +
									std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* jset dst src|imm off */
		else if (IS_OF_TYPE(node_v, jset)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_JMP_IMM(BPF_JSET, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + ", " +
				          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
		  else
		 	  c_code += "BPF_JMP_REG(BPF_JSET, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + ", " +
									std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* jne dst src|imm off */
		else if (IS_OF_TYPE(node_v, jne)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_JMP_IMM(BPF_JNE, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + ", " +
				          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
		  else
		 	  c_code += "BPF_JMP_REG(BPF_JNE, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + ", " +
									std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* jsgt dst src|imm off */
		else if (IS_OF_TYPE(node_v, jsgt)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_JMP_IMM(BPF_JSGT, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + ", " +
				          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
		  else
		 	  c_code += "BPF_JMP_REG(BPF_JSGT, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + ", " +
									std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* jsge dst src|imm off */
		else if (IS_OF_TYPE(node_v, jsge)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_JMP_IMM(BPF_JSGE, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + ", " +
				          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
		  else
		 	  c_code += "BPF_JMP_REG(BPF_JSGE, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + ", " +
									std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* jslt dst src|imm off */
		else if (IS_OF_TYPE(node_v, jslt)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_JMP_IMM(BPF_JSLT, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + ", " +
				          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
		  else
		 	  c_code += "BPF_JMP_REG(BPF_JSLT, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + ", " +
									std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* jsle dst src|imm off */
		else if (IS_OF_TYPE(node_v, jsle)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_JMP_IMM(BPF_JSLE, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + ", " +
				          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
		  else
		 	  c_code += "BPF_JMP_REG(BPF_JSLE, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + ", " +
									std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* call imm */
		else if (IS_OF_TYPE(node_v, call)) {
			error("error: call: instruction not yet supported.");
    }

    /* rel imm */
	  else if (IS_OF_TYPE(node_v, rel)) {
			c_code += "BPF_CALL_REL(" + std::to_string(get_val<int>(node_v1)) +
		            "),\n";
		}

	  /* exit */
	  else if (IS_OF_TYPE(node_v, exit_ins)) {
			c_code += "BPF_EXIT_INSN(),\n";
		}

		/* jeq32 dst src|imm off */
		else if (IS_OF_TYPE(node_v, jeq32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_JMP32_IMM(BPF_JEQ, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + ", " +
				          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
		  else
		 	  c_code += "BPF_JMP32_REG(BPF_JEQ, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + ", " +
									std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* jgt32 dst src|imm off */
		else if (IS_OF_TYPE(node_v, jgt32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_JMP32_IMM(BPF_JGT, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + ", " +
				          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
		  else
		 	  c_code += "BPF_JMP32_REG(BPF_JGT, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + ", " +
									std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* jge32 dst src|imm off */
		else if (IS_OF_TYPE(node_v, jge32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_JMP32_IMM(BPF_JGE, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + ", " +
				          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
		  else
		 	  c_code += "BPF_JMP32_REG(BPF_JGE, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + ", " +
									std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* jlt32 dst src|imm off */
		else if (IS_OF_TYPE(node_v, jlt32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_JMP32_IMM(BPF_JLT, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + ", " +
				          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
		  else
		 	  c_code += "BPF_JMP32_REG(BPF_JLT, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + ", " +
									std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* jle32 dst src|imm off */
		else if (IS_OF_TYPE(node_v, jle32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_JMP32_IMM(BPF_JLE, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + ", " +
				          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
		  else
		 	  c_code += "BPF_JMP32_REG(BPF_JLE, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + ", " +
									std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* jset32 dst src|imm off */
		else if (IS_OF_TYPE(node_v, jset32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_JMP32_IMM(BPF_JSET, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + ", " +
				          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
		  else
		 	  c_code += "BPF_JMP32_REG(BPF_JSET, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + ", " +
									std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* jne32 dst src|imm off */
		else if (IS_OF_TYPE(node_v, jne32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_JMP32_IMM(BPF_JNE, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + ", " +
				          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
		  else
		 	  c_code += "BPF_JMP32_REG(BPF_JNE, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + ", " +
									std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* jsgt32 dst src|imm off */
		else if (IS_OF_TYPE(node_v, jsgt32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_JMP32_IMM(BPF_JSGT, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + ", " +
				          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
		  else
		 	  c_code += "BPF_JMP32_REG(BPF_JSGT, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + ", " +
									std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* jsge32 dst src|imm off */
		else if (IS_OF_TYPE(node_v, jsge32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_JMP32_IMM(BPF_JSGE, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + ", " +
				          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
		  else
		 	  c_code += "BPF_JMP32_REG(BPF_JSGE, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + ", " +
									std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* jslt32 dst src|imm off */
		else if (IS_OF_TYPE(node_v, jslt32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_JMP32_IMM(BPF_JSLT, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + ", " +
				          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
		  else
		 	  c_code += "BPF_JMP32_REG(BPF_JSLT, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + ", " +
									std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

		/* jsle32 dst src|imm off */
		else if (IS_OF_TYPE(node_v, jsle32)) {
			if (IS_OF_TYPE(node_v2, imm_int))
				c_code += "BPF_JMP32_IMM(BPF_JSLE, " + get_reg_str(node_v1) + ", " +
				          std::to_string(get_val<int>(node_v2)) + ", " +
				          std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
		  else
		 	  c_code += "BPF_JMP32_REG(BPF_JSLE, " + get_reg_str(node_v1) + ", " +
				          get_reg_str(node_v2) + ", " +
									std::to_string((__s16)get_val<int>(node_v3)) + "),\n";
    }

    /* zext dst */
		else if (IS_OF_TYPE(node_v, zext)) {
			c_code += "BPF_ZEXT_REG(" + get_reg_str(node_v1) + "),\n";
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
