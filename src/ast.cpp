#include "ast.hpp"

std::vector<ast_t> ast;

std::string pp_node(Node node) {
  if      (node == regs)       return "regs";
  else if (node == dirs)       return "directive";
  else if (node == imm_int)    return "imm_int";
  else if (node == imm_float)  return "imm_float";
  else if (node == add)        return "add";
  else if (node == sub)        return "sub";
  else if (node == mul)        return "mul";
  else if (node == div_ins)    return "div";
  else if (node == or_ins)     return "or";
  else if (node == and_ins)    return "and";
  else if (node == lsh)        return "lsh";
  else if (node == rsh)        return "rsh";
  else if (node == neg)        return "neg";
  else if (node == mod)        return "mod";
  else if (node == xor_ins)    return "xor";
  else if (node == mov)        return "mov";
  else if (node == arsh)       return "arsh";
  else if (node == add32)      return "add32";
  else if (node == sub32)      return "sub32";
  else if (node == mul32)      return "mul32";
  else if (node == div32)      return "div32";
  else if (node == or32)       return "or32";
  else if (node == and32)      return "and32";
  else if (node == lsh32)      return "lsh32";
  else if (node == rsh32)      return "rsh32";
  else if (node == neg32)      return "neg32";
  else if (node == mod32)      return "mod32";
  else if (node == xor32)      return "xor32";
  else if (node == mov32)      return "mov32";
  else if (node == arsh32)     return "arsh32";
  else if (node == le16)       return "le16";
  else if (node == le32)       return "le32";
  else if (node == le64)       return "le64";
  else if (node == be16)       return "be16";
  else if (node == be32)       return "be32";
  else if (node == be64)       return "be64";
  else if (node == addx16)     return "addx16";
  else if (node == addx32)     return "addx32";
  else if (node == addx64)     return "addx64";
  else if (node == andx16)     return "andx16";
  else if (node == andx32)     return "andx32";
  else if (node == andx64)     return "andx64";
  else if (node == orx16)      return "orx16";
  else if (node == orx32)      return "orx32";
  else if (node == orx64)      return "orx64";
  else if (node == xorx16)     return "xorx16";
  else if (node == xorx32)     return "xorx32";
  else if (node == xorx64)     return "xorx64";
  else if (node == addfx16)    return "addfx16";
  else if (node == addfx32)    return "addfx32";
  else if (node == addfx64)    return "addfx64";
  else if (node == andfx16)    return "andfx16";
  else if (node == andfx32)    return "andfx32";
  else if (node == andfx64)    return "andfx64";
  else if (node == orfx16)     return "orfx16";
  else if (node == orfx32)     return "orfx32";
  else if (node == orfx64)     return "orfx64";
  else if (node == xorfx16)    return "xorfx16";
  else if (node == xorfx32)    return "xorfx32";
  else if (node == xorfx64)    return "xorfx64";
  else if (node == xchgx16)    return "xchgx16";
  else if (node == xchgx32)    return "xchgx32";
  else if (node == xchgx64)    return "xchgx64";
  else if (node == cmpxchgx16) return "cmpxchgx16";
  else if (node == cmpxchgx32) return "cmpxchgx32";
  else if (node == cmpxchgx64) return "cmpxchgx64";
  else if (node == ldmapfd)    return "ldmapfd";
  else if (node == ld64)       return "ld64";
  else if (node == ldabs8)     return "ldabs8";
  else if (node == ldabs16)    return "ldabs16";
  else if (node == ldabs32)    return "ldabs32";
  else if (node == ldabs64)    return "ldabs64";
  else if (node == ldind8)     return "ldind8";
  else if (node == ldind16)    return "ldind16";
  else if (node == ldind32)    return "ldind32";
  else if (node == ldind64)    return "ldind64";
  else if (node == ldx8)       return "ldx8";
  else if (node == ldx16)      return "ldx16";
  else if (node == ldx32)      return "ldx32";
  else if (node == ldx64)      return "ldx64";
  else if (node == st8)        return "st8";
  else if (node == st16)       return "st16";
  else if (node == st32)       return "st32";
  else if (node == st64)       return "st64";
  else if (node == stx8)       return "stx8";
  else if (node == stx16)      return "stx16";
  else if (node == stx32)      return "stx32";
  else if (node == stx64)      return "stx64";
  else if (node == stxx8)      return "stxx8";
  else if (node == stxx16)     return "stxx16";
  else if (node == stxx32)     return "stxx32";
  else if (node == stxx64)     return "stxx64";
  else if (node == ja)         return "ja";
  else if (node == jeq)        return "jeq";
  else if (node == jgt)        return "jgt";
  else if (node == jge)        return "jge";
  else if (node == jlt)        return "jlt";
  else if (node == jle)        return "jle";
  else if (node == jset)       return "jset";
  else if (node == jne)        return "jne";
  else if (node == jsgt)       return "jsgt";
  else if (node == jsge)       return "jsge";
  else if (node == jslt)       return "jslt";
  else if (node == jsle)       return "jsle";
  else if (node == call)       return "call";
  else if (node == rel)        return "rel";
  else if (node == exit_ins)   return "exit";
  else if (node == jeq32)      return "jeq32";
  else if (node == jgt32)      return "jgt32";
  else if (node == jge32)      return "jge32";
  else if (node == jlt32)      return "jlt32";
  else if (node == jle32)      return "jle32";
  else if (node == jset32)     return "jset32";
  else if (node == jne32)      return "jne32";
  else if (node == jsgt32)     return "jsgt32";
  else if (node == jsge32)     return "jsge32";
  else if (node == jslt32)     return "jslt32";
  else if (node == jsle32)     return "jsle32";
  else if (node == zext)       return "zext";
  return "node type not found";
}

std::string pp_type(Type ty) {
  if      (ty == instr) return "instruction";
  else if (ty == ident) return "identifier";
  else if (ty == direc) return "directive";
  else if (ty == imm)   return "immediate";
  else if (ty == reg)   return "register";
  else                  return "unidentified type";
}

void pp_ast(void) {
  std::string type, id, subtype;
  std::cout << "--------\nPrinting the abstract syntax tree:\n--------"
            << std::endl;
  for (uint i=0; i<ast.size(); i++) {
    type    = pp_type(ast[i].type);
    id      = ast[i].id;
    subtype = pp_node(ast[i].node_v);
    std::cout << std::setw(7) << std::setfill('0') << i+1 << ": " << id
              << pp_spaces(id, 12) << " " << type << pp_spaces(type, 16)
              << subtype;
    if (ast[i].type == instr)
      std::cout << pp_spaces(id, 16) << "off=" << ast[i].off;
    std::cout << std::endl;
  }
}
