#include "typechecker.hpp"

#define ERROR(p, ...) (error(p.line, ":", p.col, ": " ERR_STR, __VA_ARGS__))

TUPLE(Op, Pos p; Str v; Id ins;);

Op ops(Nat i, Nat j) {
  MATCH (optype(i, j)) {
    case Register:
      return {reg(i, j).pos, pp_reg(reg(i, j).reg), pp_ins(isa(j))};
    END
    case Immediate:
      return {imm(i, j).pos, STR(imm(i, j).val), pp_ins(isa(j))};
    END
    case Empty:
      return {ins(j).pos, "()", pp_ins(isa(j))};
    END
    _
      error(ERR_STR "expected a register, immediate or void, but got: ",
            pp_type(optype(i, j)), " at: [", i, ", ", j, "]");
      return {Pos{0,0}, "", ""};
    END
  }
}

void unexpected(Nat i, Nat j, Id ty) {
  Str line;
  auto [p, val, ins] = ops(i, j);
  MATCH (optype(i, j)) {
    case Empty:
      line = err_getline(ins, p.line, p.col);
    END
    _
      line = err_getline(val, p.line, p.col);
    END
  }
  ERROR(p, "unexpected operand `", val, "` passed to `", ins,
        "`. Expected an operand of type: ", ty, line);
}

void unexpected(Nat i, Nat j) {
  auto [p, val, _ins] = ops(i, j);
  Type ty             = optype(i, j);
  ERROR(p, "expected an instruction or label definition here, but instead got "
  "`", val, "` of type `", pp_type(ty), "`", err_getline(val, p.line, p.col));
}

void rest(Nat n, Nat j) {
  for (Nat i = n; i < OPERANDS; ++i)
    if (optype(i, j) != Empty)
      unexpected(i, j);
}

void typechecker() {
  for (Nat i = 0; i < ASIZE; ++i) {
    MATCH (type(i)) {
      case Instruction:
        MATCH (isa(i)) {
          /* Type check INSTR REG REG|IMM. */
          /* add, sub, mul, div, or, and, lsh, rsh, mod, xor, mov, arsh
             add32, sub32, mul32, div32, or32, and32, lsh32, rsh32, mod32,
             xor32, mov32, arsh32 */
          case add:   case sub:   case mul:   case div_:   case or_:
          case and_:  case lsh:   case rsh:   case mod:    case xor_:
          case mov:   case arsh:  case add32: case sub32:  case mul32:
          case div32: case or32:  case and32: case lsh32:  case rsh32:
          case mod32: case xor32: case mov32: case arsh32:
            if (optype(FST, i) != Register)
              unexpected(FST, i, "REG");
            if (optype(SND, i) != Register && optype(SND, i) != Immediate)
              unexpected(SND, i, "REG|IMM");
            rest(TRD, i);
          END
          /* Type check INSTR REG. */
          /* le16, le32, le64, be16, be32, be64,
             neg, neg32,
             zext */
          case le16: case le32:  case le64: case be16: case be32: case be64:
          case neg:  case neg32: case zext:
            if (optype(FST, i) != Register)
              unexpected(FST, i, "REG");
            rest(SND, i);
          END
          /* Type check INSTR REG IMM IMM. */
          /* st8, st16, st32, st64 */
          case st8: case st16: case st32: case st64:
            if (optype(FST, i) != Register)
              unexpected(FST, i, "REG");
            if (optype(SND, i) != Immediate)
              unexpected(SND, i, "IMM");
            if (optype(TRD, i) != Immediate)
              unexpected(TRD, i, "IMM");
            rest(FRT, i);
          END
          /* Type check INSTR REG IMM. */
          /* ldmapfd, ld64, ldind8, ldind16, ldind32, ldind64 */
          case ldmapfd: case ld64: case ldind8: case ldind16: case ldind32:
          case ldind64:
            if (optype(FST, i) != Register)
              unexpected(FST, i, "REG");
            if (optype(SND, i) != Immediate)
              unexpected(SND, i, "IMM");
            rest(TRD, i);
          END
          /* Type check INSTR IMM. */
          /* ldabs8, ldabs16, ldabs32, ldabs64,
             ja, call, rel */
          case ldabs8: case ldabs16: case ldabs32: case ldabs64: case ja:
          case call:   case rel:
            if (optype(FST, i) != Immediate)
              unexpected(FST, i, "IMM");
            rest(SND, i);
          END
          /* Type check INSTR REG REG|IMM IMM. */
          /* jeq, jgt, jge, jlt, jle, jset, jne, jsgt, jsge, jslt, jsle,
             jeq32, jgt32, jge32, jlt32, jle32, jset32, jne32, jsgt32, jsge32,
             jslt32, jsle32 */
          case jeq:    case jgt:    case jge:    case jlt:    case jle:
          case jset:   case jne:    case jsgt:   case jsge:   case jslt:
          case jsle:   case jeq32:  case jgt32:  case jge32:  case jlt32:
          case jle32:  case jset32: case jne32:  case jsgt32: case jsge32:
          case jslt32: case jsle32:
            if (optype(FST, i) != Register)
              unexpected(FST, i, "REG");
            if (optype(SND, i) != Register && optype(SND, i) != Immediate)
              unexpected(SND, i, "REG|IMM");
            if (optype(TRD, i) != Immediate)
              unexpected(TRD, i, "IMM");
            rest(FRT, i);
          END
          /* Type check EXIT. */
          case exit_:
            rest(FST, i);
          END
          /* Type check INSTR REG REG IMM. */
          /* addx16, addx32, addx64, andx16, andx32, andx64, orx16, orx32, orx64,
             xorx16, xorx32, xorx64, addfx16, addfx32, addfx64, andfx16, andfx32,
             andfx64, orfx16, orfx32, orfx64, xorfx16, xorfx32, xorfx64, xchgx16,
             xchgx32, xchgx64, cmpxchgx16, cmpxchgx32, cmpxchgx64,
             ldx8, ldx16, ldx32, ldx64, stx8, stx16, stx32, stx64, stxx8, stxx16,
             stxx32, stxx64 */
          case addx16:  case addx32:  case addx64:  case andx16:  case andx32:
          case andx64:  case orx16:   case orx32:   case orx64:   case xorx16:
          case xorx32:  case xorx64:  case addfx16: case addfx32: case addfx64:
          case andfx16: case andfx32: case andfx64: case orfx16:  case orfx32:
          case orfx64:  case xorfx16: case xorfx32: case xorfx64: case xchgx16:
          case xchgx32: case xchgx64: case ldx8:    case ldx16:   case ldx32:
          case ldx64:   case stx8:    case stx16:   case stx32:   case stx64:
          case stxx8:   case stxx16:  case stxx32:  case stxx64:
          case cmpxchgx16: case cmpxchgx32: case cmpxchgx64:
            if (optype(FST, i) != Register)
              unexpected(FST, i, "REG");
            if (optype(SND, i) != Register)
              unexpected(SND, i, "REG");
            if (optype(TRD, i) != Immediate)
              unexpected(TRD, i, "IMM");
            rest(FRT, i);
          END
          _
            error(ERR_STR "undefined instruction in the AST: `", pp_ins(isa(i)),
                  "` categorical variable: ", isa(i));
          END
        }
      END
      case Label:
        continue;
      END
      _
        error(ERR_STR "expected an instruction or label, but got: ",
              pp_type(type(i)));
      END
    }
  }
}
