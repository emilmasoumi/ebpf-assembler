/*
  Type check the instructions of the bytecode in the abstract syntax tree.
*/

#include "typechecker.h"

static inline void unexpected_op_err(uint line, uint col, ident_t id1,
                                                          ident_t id2) {
  error(line, ":", col, ": type error: unexpected operand ``", id1,
        "`` passed to ``", id2, "``", err_getline(id2, line, col));
}

static inline void forward_err(uint line, uint col, ident_t id, Type ty) {
  error(line, ":", col, ": type error: expected an instruction or directive "
        "here, but instead got ``", id, "`` of type ``", pp_type(ty), "``",
        err_getline(id, line, col));
}

void typechecker(void) {
  std::string id;
  ast_t node;
  uint size;
  uint ops;
  Type type;
  Node node_v;
  uint line, col;

  size = absyn_tree.size();

  for (uint i=0; i<size; i++) {
    node   = absyn_tree[i];
    id     = node.id;
    type   = node.type;
    node_v = node.node_v;
    line   = node.line;
    col    = node.col;
    ops    = node.arg_num;

    if (type == instr) {
      if (i+ops >= size)
        error(line, ":", col, ": type error: instruction ", id, " expects ",
              ops, " operands, but was here given ", size-i-1, " operand(s)");

      /* Type check INSTR REG REG|IMM. */
      /* add, sub, mul, div, or, and, lsh, rsh, mod, xor, mov, arsh
         add32, sub32, mul32, div32, or32, and32, lsh32, rsh32, mod32, xor32,
         mov32, arsh32 */
      if (node_v == add     || node_v == sub    || node_v == mul     ||
          node_v == div_ins || node_v == or_ins || node_v == and_ins ||
          node_v == lsh     || node_v == rsh    || node_v == mod     ||
          node_v == xor_ins || node_v == mov    || node_v == arsh    ||
          node_v == add32   || node_v == sub32  || node_v == mul32   ||
          node_v == div32   || node_v == or32   || node_v == and32   ||
          node_v == lsh32   || node_v == rsh32  || node_v == mod32   ||
          node_v == xor32   || node_v == mov32  || node_v == arsh32) {
        if (absyn_tree[i+1].type != reg)
          unexpected_op_err(line, col, absyn_tree[i+1].id, id);
        else if (absyn_tree[i+2].type != reg && absyn_tree[i+2].type != imm)
          unexpected_op_err(line, col, absyn_tree[i+2].id, id);
        else if (i+3 < size && absyn_tree[i+3].type != instr &&
                 absyn_tree[i+3].type != direc)
          forward_err(absyn_tree[i+3].line, absyn_tree[i+3].col,
                      absyn_tree[i+3].id,   absyn_tree[i+3].type);
      }

      /* Type check INSTR REG. */
      /* le16, le32, le64, be16, be32, be64,
         neg, neg32,
         zext */
      else if (node_v == le16 || node_v == le32  || node_v == le64  ||
               node_v == be16 || node_v == be32  || node_v == be64  ||
               node_v == neg  || node_v == neg32 || node_v == zext) {
        if (absyn_tree[i+1].type != reg)
          unexpected_op_err(line, col, absyn_tree[i+1].id, id);
        else if (i+2 < size && absyn_tree[i+2].type != instr &&
                 absyn_tree[i+2].type != direc)
          forward_err(absyn_tree[i+2].line, absyn_tree[i+2].col,
                      absyn_tree[i+2].id,   absyn_tree[i+2].type);
      }

      /* Type check INSTR REG IMM IMM. */
      /* st8, st16, st32, st64 */
      else if (node_v == st8  || node_v == st16 ||
               node_v == st32 || node_v == st64) {
        if (absyn_tree[i+1].type != reg)
          unexpected_op_err(line, col, absyn_tree[i+1].id, id);
        else if (absyn_tree[i+2].type != imm)
          unexpected_op_err(line, col, absyn_tree[i+2].id, id);
        else if (absyn_tree[i+3].type != imm)
          unexpected_op_err(line, col, absyn_tree[i+3].id, id);
        else if (i+4 < size && absyn_tree[i+4].type != instr &&
                 absyn_tree[i+4].type != direc)
          forward_err(absyn_tree[i+4].line, absyn_tree[i+4].col,
                      absyn_tree[i+4].id,   absyn_tree[i+4].type);
      }

      /* Type check INSTR REG IMM. */
      /* ldmapfd, ld64, ldind8, ldind16, ldind32, ldind64 */
      else if (node_v == ldmapfd || node_v == ld64    ||
               node_v == ldind8  || node_v == ldind16 ||
               node_v == ldind32 || node_v == ldind64) {
        if (absyn_tree[i+1].type != reg)
          unexpected_op_err(line, col, absyn_tree[i+1].id, id);
        else if (absyn_tree[i+2].type != imm)
          unexpected_op_err(line, col, absyn_tree[i+2].id, id);
        else if (i+3 < size && absyn_tree[i+3].type != instr &&
                 absyn_tree[i+3].type != direc)
          forward_err(absyn_tree[i+3].line, absyn_tree[i+3].col,
                      absyn_tree[i+3].id,   absyn_tree[i+3].type);
      }

      /* Type check INSTR IMM. */
      /* ldabs8, ldabs16, ldabs32, ldabs64,
         ja, call, rel */
      else if (node_v == ldabs8  || node_v == ldabs16 || node_v == ldabs32 ||
               node_v == ldabs64 || node_v == ja      || node_v == call    ||
               node_v == rel) {
        if (absyn_tree[i+1].type != imm)
          unexpected_op_err(line, col, absyn_tree[i+1].id, id);
        else if (i+2 < size && absyn_tree[i+2].type != instr &&
                 absyn_tree[i+2].type != direc)
          forward_err(absyn_tree[i+2].line, absyn_tree[i+2].col,
                      absyn_tree[i+2].id,   absyn_tree[i+2].type);
      }

      /* Type check INSTR REG REG|IMM IMM. */
      /* jeq, jgt, jge, jlt, jle, jset, jne, jsgt, jsge, jslt, jsle,
         jeq32, jgt32, jge32, jlt32, jle32, jset32, jne32, jsgt32, jsge32,
         jslt32, jsle32 */
      else if (node_v == jeq    || node_v == jgt    || node_v == jge    ||
               node_v == jlt    || node_v == jle    || node_v == jset   ||
               node_v == jne    || node_v == jsgt   || node_v == jsge   ||
               node_v == jslt   || node_v == jsle   || node_v == jeq32  ||
               node_v == jgt32  || node_v == jge32  || node_v == jlt32  ||
               node_v == jle32  || node_v == jset32 || node_v == jne32  ||
               node_v == jsgt32 || node_v == jsge32 || node_v == jslt32 ||
               node_v == jsle32) {
        if (absyn_tree[i+1].type != reg)
          unexpected_op_err(line, col, absyn_tree[i+1].id, id);
        else if (absyn_tree[i+2].type != reg && absyn_tree[i+2].type != imm)
          unexpected_op_err(line, col, absyn_tree[i+2].id, id);
        else if (absyn_tree[i+3].type != imm)
          unexpected_op_err(line, col, absyn_tree[i+3].id, id);
        else if (i+4 < size && absyn_tree[i+4].type != instr &&
                 absyn_tree[i+4].type != direc)
          forward_err(absyn_tree[i+4].line, absyn_tree[i+4].col,
                      absyn_tree[i+4].id,   absyn_tree[i+4].type);
      }

      /* Type check EXIT. */
      else if (node_v == exit_ins) {
        if (i+1 < size && absyn_tree[i+1].type != instr &&
            absyn_tree[i+1].type != direc)
         forward_err(absyn_tree[i+1].line, absyn_tree[i+1].col,
                     absyn_tree[i+1].id,   absyn_tree[i+1].type);
      }

      /* Type check INSTR REG REG IMM. */
      /* addx16, addx32, addx64, andx16, andx32, andx64, orx16, orx32, orx64,
         xorx16, xorx32, xorx64, addfx16, addfx32, addfx64, andfx16, andfx32,
         andfx64, orfx16, orfx32, orfx64, xorfx16, xorfx32, xorfx64, xchgx16,
         xchgx32, xchgx64, cmpxchgx16, cmpxchgx32, cmpxchgx64,
         ldx8, ldx16, ldx32, ldx64, stx8, stx16, stx32, stx64, stxx8, stxx16,
         stxx32, stxx64 */
      else {
        if (absyn_tree[i+1].type != reg)
          unexpected_op_err(line, col, absyn_tree[i+1].id, id);
        else if (absyn_tree[i+2].type != reg)
          unexpected_op_err(line, col, absyn_tree[i+2].id, id);
        else if (absyn_tree[i+3].type != imm)
          unexpected_op_err(line, col, absyn_tree[i+3].id, id);
        else if (i+4 < size && absyn_tree[i+4].type != instr &&
                 absyn_tree[i+4].type != direc)
          forward_err(absyn_tree[i+4].line, absyn_tree[i+4].col,
                      absyn_tree[i+4].id,   absyn_tree[i+4].type);
      }

    }

    /* Type check directive */
    else if (type ==  direc) {
      if (i+1 < size && absyn_tree[i+1].type != instr &&
          absyn_tree[i+1].type != direc)
        forward_err(absyn_tree[i+1].line, absyn_tree[i+1].col,
                    absyn_tree[i+1].id,   absyn_tree[i+1].type);
    }

  }

}
