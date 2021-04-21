#ifndef SYMTAB
#define SYMTAB

#include <string>
#include <vector>
#include <iostream>
#include <iomanip>
#include "utils.h"

typedef std::string ident_t;
typedef uint line_t;
typedef uint col_t;

#define dealloc_symtab() (symtab.erase(symtab.begin(), symtab.end()))

/*
  Symbol table for bytecode where each entry contains:
  types, identifiers and their position.
*/

typedef enum {instr, ident, direc, imm, reg} Type;

struct symtab_t {
  Type type;
  ident_t id;
  line_t line;
  col_t col;
};

extern std::vector<struct symtab_t> symtab;

std::vector<struct symtab_t> lookup(ident_t);
std::vector<struct symtab_t> lookup_typesafe(ident_t, Type);
uint num_instr(void);
std::string pp_type(Type);
void pp_symtab(void);

#endif
