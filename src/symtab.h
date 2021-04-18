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
  symbols, identifiers and their position.
*/

typedef enum {instr, ident, direc, imm, reg} Symbol;

struct symtab_t {
  Symbol type;
  ident_t id;
  line_t line;
  col_t col;
};

extern std::vector<struct symtab_t> symtab;

std::vector<struct symtab_t> lookup(ident_t);
std::vector<struct symtab_t> lookup_typesafe(ident_t, Symbol);
uint num_instr(void);
std::string pp_symbol(Symbol);
void pp_symtab(void);

#endif
