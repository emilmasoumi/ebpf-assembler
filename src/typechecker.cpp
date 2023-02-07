#include "typechecker.hpp"

#define unexpected_op_err(line, col, id1, id2)                       \
  (error(line, ":", col, ": type error: unexpected operand ``", id1, \
         "`` passed to ``", id2, "``", err_getline(id2, line, col)))

#define forward_err(line, col, id, ty)                               \
  (error(line, ":", col, ": type error: expected an instruction or " \
         "directive here, but instead got ``", id, "`` of type ``",  \
         pp_type(ty), "``", err_getline(id, line, col)))

void typechecker(void) {
  std::string id;
  ast_t node;
  uint  size;
  uint  ops;
  Type  type;
  Node  node_v;
  uint  line, col;

  size = ast.size();

  for (uint i=0; i<size; i++) {
    node   = ast[i];
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

      switch (node_v) {
      /* Type check INSTR REG REG|IMM. */
      /* add, sub, mul, div, or, and, lsh, rsh, mod, xor, mov, arsh
         add32, sub32, mul32, div32, or32, and32, lsh32, rsh32, mod32, xor32,
         mov32, arsh32 */
        case add:     case sub:   case mul:   case div_ins: case or_ins:
        case and_ins: case lsh:   case rsh:   case mod:     case xor_ins:
        case mov:     case arsh:  case add32: case sub32:   case mul32:
        case div32:   case or32:  case and32: case lsh32:   case rsh32:
        case mod32:   case xor32: case mov32: case arsh32:
          if (ast[i+1].type != reg)
            unexpected_op_err(line, col, ast[i+1].id, id);
          else if (ast[i+2].type != reg && ast[i+2].type != imm)
            unexpected_op_err(line, col, ast[i+2].id, id);
          else if (i+3 < size && ast[i+3].type != instr &&
                   ast[i+3].type != direc)
            forward_err(ast[i+3].line, ast[i+3].col,
                        ast[i+3].id,   ast[i+3].type);
        break;
        /* Type check INSTR REG. */
        /* le16, le32, le64, be16, be32, be64,
           neg, neg32,
           zext */
        case le16: case le32:  case le64: case be16: case be32: case be64:
        case  neg: case neg32: case zext:
          if (ast[i+1].type != reg)
            unexpected_op_err(line, col, ast[i+1].id, id);
          else if (i+2 < size && ast[i+2].type != instr &&
                   ast[i+2].type != direc)
            forward_err(ast[i+2].line, ast[i+2].col,
                        ast[i+2].id,   ast[i+2].type);
        break;
        /* Type check INSTR REG IMM IMM. */
        /* st8, st16, st32, st64 */
        case st8: case st16: case st32: case st64:
          if (ast[i+1].type != reg)
            unexpected_op_err(line, col, ast[i+1].id, id);
          else if (ast[i+2].type != imm)
            unexpected_op_err(line, col, ast[i+2].id, id);
          else if (ast[i+3].type != imm)
            unexpected_op_err(line, col, ast[i+3].id, id);
          else if (i+4 < size && ast[i+4].type != instr &&
                   ast[i+4].type != direc)
            forward_err(ast[i+4].line, ast[i+4].col,
                        ast[i+4].id,   ast[i+4].type);
        break;
        /* Type check INSTR REG IMM. */
        /* ldmapfd, ld64, ldind8, ldind16, ldind32, ldind64 */
        case ldmapfd: case ld64: case ldind8: case ldind16: case ldind32:
        case ldind64:
          if (ast[i+1].type != reg)
            unexpected_op_err(line, col, ast[i+1].id, id);
          else if (ast[i+2].type != imm)
            unexpected_op_err(line, col, ast[i+2].id, id);
          else if (i+3 < size && ast[i+3].type != instr &&
                   ast[i+3].type != direc)
            forward_err(ast[i+3].line, ast[i+3].col,
                        ast[i+3].id,   ast[i+3].type);
        break;
        /* Type check INSTR IMM. */
        /* ldabs8, ldabs16, ldabs32, ldabs64,
           ja, call, rel */
        case ldabs8: case ldabs16: case ldabs32: case ldabs64: case ja:
        case call:   case rel:
          if (ast[i+1].type != imm)
            unexpected_op_err(line, col, ast[i+1].id, id);
          else if (i+2 < size && ast[i+2].type != instr &&
                   ast[i+2].type != direc)
            forward_err(ast[i+2].line, ast[i+2].col,
                        ast[i+2].id,   ast[i+2].type);
        break;
        /* Type check INSTR REG REG|IMM IMM. */
        /* jeq, jgt, jge, jlt, jle, jset, jne, jsgt, jsge, jslt, jsle,
           jeq32, jgt32, jge32, jlt32, jle32, jset32, jne32, jsgt32, jsge32,
           jslt32, jsle32 */
        case jeq:    case jgt:    case jge:    case jlt:    case jle:
        case jset:   case jne:    case jsgt:   case jsge:   case jslt:
        case jsle:   case jeq32:  case jgt32:  case jge32:  case jlt32:
        case jle32:  case jset32: case jne32:  case jsgt32: case jsge32:
        case jslt32: case jsle32:
          if (ast[i+1].type != reg)
            unexpected_op_err(line, col, ast[i+1].id, id);
          else if (ast[i+2].type != reg && ast[i+2].type != imm)
            unexpected_op_err(line, col, ast[i+2].id, id);
          else if (ast[i+3].type != imm)
            unexpected_op_err(line, col, ast[i+3].id, id);
          else if (i+4 < size && ast[i+4].type != instr &&
                   ast[i+4].type != direc)
            forward_err(ast[i+4].line, ast[i+4].col,
                        ast[i+4].id,   ast[i+4].type);
        break;
        /* Type check EXIT. */
        case exit_ins:
        if (i+1 < size && ast[i+1].type != instr &&
            ast[i+1].type != direc)
         forward_err(ast[i+1].line, ast[i+1].col,
                     ast[i+1].id,   ast[i+1].type);
        break;
        default:
        /* Type check INSTR REG REG IMM. */
        /* addx16, addx32, addx64, andx16, andx32, andx64, orx16, orx32, orx64,
           xorx16, xorx32, xorx64, addfx16, addfx32, addfx64, andfx16, andfx32,
           andfx64, orfx16, orfx32, orfx64, xorfx16, xorfx32, xorfx64, xchgx16,
           xchgx32, xchgx64, cmpxchgx16, cmpxchgx32, cmpxchgx64,
           ldx8, ldx16, ldx32, ldx64, stx8, stx16, stx32, stx64, stxx8, stxx16,
           stxx32, stxx64 */
        if (ast[i+1].type != reg)
          unexpected_op_err(line, col, ast[i+1].id, id);
        else if (ast[i+2].type != reg)
          unexpected_op_err(line, col, ast[i+2].id, id);
        else if (ast[i+3].type != imm)
          unexpected_op_err(line, col, ast[i+3].id, id);
        else if (i+4 < size && ast[i+4].type != instr &&
                 ast[i+4].type != direc)
          forward_err(ast[i+4].line, ast[i+4].col,
                      ast[i+4].id,   ast[i+4].type);
      }
    }

    /* Type check directive */
    else if (type ==  direc) {
      if (i+1 < size && ast[i+1].type != instr &&
          ast[i+1].type != direc)
        forward_err(ast[i+1].line, ast[i+1].col,
                    ast[i+1].id,   ast[i+1].type);
    }
  }
}
