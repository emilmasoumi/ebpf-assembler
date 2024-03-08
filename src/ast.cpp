#include "ast.hpp"

#define OFFW std::setw(7) << std::setfill('0')

AST ast;
Str bytecode;

void dealloc() {
  for (Nat i = 0; i < ASIZE; ++i) {
    MATCH (type(i)) {
      case Label:
        if (lab(i).lname != nullptr)
          delete[] lab(i).lname;
      END
      case Instruction:
        for (Nat j = 0; j < OPERANDS; ++j) {
          if (optype(j, i) == Reference && ref(j, i).id != nullptr)
            delete[] ref(j, i).id;
        }
      END
      _
        error(ERR_STR "unexpected statement type: ", pp_type(type(i)));
      END
    }
  }
}

Id toId(Str s) {
  char* mem = new char[s.size() + 1];
  memcpy(mem, s.c_str(), s.size());
  mem[s.size()] = '\0';
  return mem;
}

Stat& stat(Nat i) { return ast[i]; }

ISA& isa(Nat i) { return ast[i].ins.ins; }
Ins& ins(Nat i) { return ast[i].ins; }
Lab& lab(Nat i) { return ast[i].lab; }

Type& type(  Nat i)        { return ast[i].ty; }
Type& optype(Nat i, Nat j) { return ast[j].ins.ops[i].ty; }

Imm& imm(Nat i, Nat j) { return ast[j].ins.ops[i].imm; }
Reg& reg(Nat i, Nat j) { return ast[j].ins.ops[i].reg; }
Ref& ref(Nat i, Nat j) { return ast[j].ins.ops[i].var; }

Id pp_stat(Nat i) {
  MATCH (type(i)) {
    case Instruction: return pp_ins(isa(i)); END
    case Label:       return lab(i).lname;   END
    _                 return "_";            END
  }
}

Id pp_type(Type ty) {
  MATCH (ty) {
    case Instruction: return "Instruction"; END
    case Immediate:   return "Immediate";   END
    case Register:    return "Register";    END
    case Label:       return "Label";       END
    case Reference:   return "Reference";   END
    case Empty:       return "Empty";       END
    _                 return "??";          END
  }
}

Id pp_reg(Regs reg) {
  for (auto [s, r] : registers)
    if (reg == r)
      return s;
  return "???";
}

Id pp_ins(ISA ins) {
  for (auto [s, i] : instructions)
    if (ins == i)
      return s;
  return "???";
}

#define PP_POS(x) "(" << x.pos.line << " : Nat, " \
                      << x.pos.col  << " : Nat) : Pos"

void pp_ops(Nat j) {
  IO << "[";
  for (Nat i = 0; i < OPERANDS; ++i) {
    if (i > 0)
      IO << Str(25, ' ');
    MATCH (optype(i, j)) {
      case Empty:
        IO << "(NULL : Reg|Imm, Empty : Type), ..." << "]\n";
        return;
      END
      case Register:
        IO << "(" << pp_reg(reg(i, j).reg);
        IO << " : Reg, ";
        IO << PP_POS(reg(i, j));
        IO << ", Register : Type)";
      END
      case Immediate:
        IO << "(" << imm(i, j).val;
        IO << " : Imm, ";
        IO << PP_POS(imm(i, j));
        IO << ", Immediate : Type)";
      END
      _
        error(ERR_STR "unexpected type in the operands: ", pp_type(optype(i, j)));
      END
    }
    if (i + 1 != OPERANDS)
      IO << ",\n";
  }
  IO << "]\n";
}

void pp_ast() {
  IO << "--------\nPrinting the abstract syntax tree:\n--------\n";
  for (Nat i = 0; i < ASIZE; ++i) {
    IO << OFFW << i + 1 << ": ";
    IO << "Stat -> ";
    MATCH (type(i)) {
      case Instruction:
        IO << "Ins -> ";
        pp_ops(i);
        IO << Str(21, ' ') << "-> (";
        IO << pp_ins(isa(i)) << " : ISA, ";
        IO << PP_POS(ins(i));
        IO << ")\n";
      END
      case Label:
        IO << "Lab -> (";
        IO << lab(i).lname << " : Id, ";
        IO << lab(i).off   << " : Nat, ";
        IO << PP_POS(lab(i));
        IO << ")\n";
      END
      _
        error(ERR_STR "unexpected type in the AST: ", pp_type(type(i)));
      END
    }
    IO << Str(14, ' ') << "-> " << pp_type(type(i)) << " : Type\n";
  }
  IO << std::flush;
}
