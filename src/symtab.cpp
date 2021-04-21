/*
  Symbol table.
*/
#include "symtab.h"

std::vector<struct symtab_t> symtab;

std::vector<struct symtab_t> lookup(ident_t id) {
  std::vector<struct symtab_t> sub_symtab;
  for (struct symtab_t entry : symtab)
    if (entry.id == id)
      sub_symtab.push_back(entry);

  return sub_symtab;
}

std::vector<struct symtab_t> lookup_typesafe(ident_t id, Type ty) {
  std::vector<struct symtab_t> sub_symtab;
  for (struct symtab_t entry : symtab)
    if (entry.id == id && entry.type == ty)
      sub_symtab.push_back(entry);

  return sub_symtab;
}

uint num_instr(void) {
  uint count = 0;
  for (struct symtab_t entry : symtab) {
    if (entry.type == instr)
      count++;
  }
  return count;
}

std::string pp_type(Type ty) {
  if      (ty == instr) return "instruction";
  else if (ty == ident) return "identifier";
  else if (ty == direc) return "directive";
  else if (ty == imm)   return "immediate";
  else if (ty == reg)   return "register";
  else                  return "unidentified type";
}

void pp_symtab(void) {
  std::cout << "--------\nPrinting the symbol table:\n--------" << std::endl;
  std::string sym, id;
  uint line, col, i = 1;
  for (struct symtab_t entry : symtab) {
    sym  = pp_type(entry.type);
    id   = entry.id;
    line = entry.line;
    col  = entry.col;
    std::cout << std::setw(7) << std::setfill('0') << i << ": " << sym
              << pp_spaces(sym , 16) << id << pp_spaces(id, 12) << line
              << pp_spaces(std::to_string(line), 8) << col << std::endl;
    i++;
  }
}
