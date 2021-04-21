/*
  Top-down recursive descent parser. Parses the tokens from the lexer and
  evaluates statements before passing them to the abstract syntax tree.
*/

#include "parser.h"
#include <algorithm>

std::vector<struct var>vnames;

#define parse_err(line, col, id, msg) \
  (error(line, ":", col, ": parse error: ", msg, err_getline(id, line, col)))

static inline bool is_number(std::string s) {
  return (!s.empty() && std::all_of(s.begin(), s.end(), ::isdigit));
}

static inline bool is_hex(std::string s) {
  return
    (s.compare(0, 2, "0x") == 0 && s.size() > 2
     && s.find_first_not_of("0123456789abcdefABCDEF", 2) == std::string::npos);
}

static inline bool is_decimal(std::string s) {
  if (s.size() < 3)
    return 0;
  return (s[0] != '.' && s[s.size()-1] != '.'
         && std::count(s.begin(), s.end(), '.') == 1
         && s.find_first_not_of("0123456789.", 0) == std::string::npos);
}

static inline bool is_negative(std::string s) {
  if (s.size() < 2)
    return 0;
  std::string val = s.substr(1, s.size()-1);
  return (s[0] == '-' && (is_number(val) || is_hex(val) || is_decimal(val)));
}

static inline bool is_reg(std::string id) {
  for (std::string r : registers)
    if (r == id)
      return 1;
  return 0;
}

static inline bool is_instr(std::string id) {
  for (std::string ins : instructions)
    if (ins == id)
      return 1;
  return 0;
}

template <typename T>
static inline int id_idx(ident_t vname, std::vector<T>vec) {
  for (uint i=0; i<vec.size(); i++)
    if (vec[i].name == vname)
      return i;
  return -1;
}

static inline ident_t vname_val(ident_t id) {
  for (struct var vname : vnames)
    if (vname.name == id)
      return vname.val;
  error("error: ", id, " is undefined");
  return " ";
}

void parse_newline(std::string& lexeme, uint& line, uint& col, bool& comment) {
  if (!lexeme.empty())
    parse_lexeme(lexeme, line, col);
  comment = 0;
  col     = 1;
  line++;
}

void parse_directive(std::string& lexeme, uint line, uint col) {
  if (lexeme.empty() && !symtab.empty() && symtab.back().type == ident)
    symtab.back().type = direc;
  else
    symtab.push_back({direc, lexeme, line, col});

  ident_t id = symtab.back().id;

  parse_err(symtab.back().line, symtab.back().col, id,
            "Directives are not supported");

  if (is_number(id) || is_hex(id) || is_decimal(id) || is_negative(id) ||
      is_instr(id)  || is_reg(id))
    parse_err(line, col, id, "directive: ``"+id+"`` cannot be a number or keyword");

  lexeme.clear();
}

void parse_lexeme(std::string& lexeme, uint line, uint col) {
  if(lexeme == ";")
    ;
  else if (is_decimal(lexeme))
    parse_err(line, col, lexeme, "floating-point format is unsupported in eBPF");
  else if (is_instr(lexeme))
    symtab.push_back({instr, lexeme, line, col});
  else if (is_reg(lexeme))
    symtab.push_back({reg, lexeme, line, col});
  else if (is_number(lexeme)  || is_hex(lexeme) ||
           is_decimal(lexeme) || is_negative(lexeme))
    symtab.push_back({imm, lexeme, line, col});
  else
    symtab.push_back({ident, lexeme, line, col});

  lexeme.clear();
}

static inline void push_instr(Node node, uint& offset, Type ty, ident_t id,
                              uint line, uint col) {
  absyn_tree.push_back({node, ty, id, offset, line, col});
}

static inline void push_reg(Type ty, ident_t id, uint line, uint col) {
  absyn_tree.push_back({regs, ty, id, 0, line, col});
}

static inline void push_var(uint& idx, ident_t id, uint line, uint col) {
  if (idx+2 >= symtab.size())
    parse_err(line, col, id, "var expects at least two operands");
  else if (symtab[idx+1].type != ident)
    parse_err(line, col, id, "first operand of `var` must be an identifier");
  else if (symtab[idx+2].type != imm && symtab[idx+2].type != ident)
    parse_err(line, col, id, "second operand of `var` must be an immediate or variable");

  idx++;
  ident_t vname = symtab[idx].id;
  idx++;

  std::string v = symtab[idx].id;
  if (symtab[idx].type != imm)
    v = vname_val(v);

  int vname_index = id_idx(vname, vnames);
  if (vname_index < 0)
    vnames.push_back({vname, v});
  else
    vnames[vname_index].val = v;
}

static inline void push_imm(uint &idx, uint line, uint col) {
  Type type = symtab[idx].type;
  ident_t id  = symtab[idx].id;
  int i;

  if (type == ident)
    if (is_hex(vname_val(id)))
      i = std::stoi(vname_val(id), 0, 16);
    else
      i = std::stoi(vname_val(id));
  else if (type == imm)
    if (is_hex(id))
      i = std::stoi(id, 0, 16);
    else
      i = std::stoi(id);
  else
    parse_err(line, col, id, "not an immediate");

  absyn_tree.push_back({imm_int, imm, std::to_string(i), 0, line, col});
}

static inline void push_id(uint& idx, ident_t id, uint line, uint col) {
  if (id_idx(id, vnames) >= 0)
    push_imm(idx, line, col);
  else
    parse_err(line, col, id, "undefined identifier: ``"+id+"``");
}

/*
  Parses the symbol table to an abstract syntax tree.
*/
void parser(void) {

  if (num_instr() < 1)
    error("1:1: parse error: expected at least one instruction");

  uint offset;
  offset = 0;

  struct symtab_t entry;
  Type ty;
  ident_t id;
  uint line, col;

  for (uint i=0; i < symtab.size(); i++) {

    entry = symtab[i];
    id    = entry.id;
    ty    = entry.type;
    line  = entry.line;
    col   = entry.col;

    /* Instructions */
    if (ty == instr) {
      if (id == "add")             push_instr(add, offset, ty, id, line, col);
      else if (id == "sub")        push_instr(sub, offset, ty, id, line, col);
      else if (id == "mul")        push_instr(mul, offset, ty, id, line, col);
      else if (id == "div")        push_instr(div_ins, offset, ty, id, line, col);
      else if (id == "or")         push_instr(or_ins, offset, ty, id, line, col);
      else if (id == "and")        push_instr(and_ins, offset, ty, id, line, col);
      else if (id == "lsh")        push_instr(lsh, offset, ty, id, line, col);
      else if (id == "rsh")        push_instr(rsh, offset, ty, id, line, col);
      else if (id == "neg")        push_instr(neg, offset, ty, id, line, col);
      else if (id == "mod")        push_instr(mod, offset, ty, id, line, col);
      else if (id == "xor")        push_instr(xor_ins, offset, ty, id, line, col);
      else if (id == "mov")        push_instr(mov, offset, ty, id, line, col);
      else if (id == "arsh")       push_instr(arsh, offset, ty, id, line, col);
      else if (id == "add32")      push_instr(add32, offset, ty, id, line, col);
      else if (id == "sub32")      push_instr(sub32, offset, ty, id, line, col);
      else if (id == "mul32")      push_instr(mul32, offset, ty, id, line, col);
      else if (id == "div32")      push_instr(div32, offset, ty, id, line, col);
      else if (id == "or32")       push_instr(or32, offset, ty, id, line, col);
      else if (id == "and32")      push_instr(and32, offset, ty, id, line, col);
      else if (id == "lsh32")      push_instr(lsh32, offset, ty, id, line, col);
      else if (id == "rsh32")      push_instr(rsh32, offset, ty, id, line, col);
      else if (id == "neg32")      push_instr(neg32, offset, ty, id, line, col);
      else if (id == "mod32")      push_instr(mod32, offset, ty, id, line, col);
      else if (id == "xor32")      push_instr(xor32, offset, ty, id, line, col);
      else if (id == "mov32")      push_instr(mov32, offset, ty, id, line, col);
      else if (id == "arsh32")     push_instr(arsh32, offset, ty, id, line, col);
      else if (id == "le16")       push_instr(le16, offset, ty, id, line, col);
      else if (id == "le32")       push_instr(le32, offset, ty, id, line, col);
      else if (id == "le64")       push_instr(le64, offset, ty, id, line, col);
      else if (id == "be16")       push_instr(be16, offset, ty, id, line, col);
      else if (id == "be32")       push_instr(be32, offset, ty, id, line, col);
      else if (id == "be64")       push_instr(be64, offset, ty, id, line, col);
      else if (id == "addx16")     push_instr(addx16, offset, ty, id, line, col);
      else if (id == "addx32")     push_instr(addx32, offset, ty, id, line, col);
      else if (id == "addx64")     push_instr(addx64, offset, ty, id, line, col);
      else if (id == "andx16")     push_instr(andx16, offset, ty, id, line, col);
      else if (id == "andx32")     push_instr(andx32, offset, ty, id, line, col);
      else if (id == "andx64")     push_instr(andx64, offset, ty, id, line, col);
      else if (id == "orx16")      push_instr(orx16, offset, ty, id, line, col);
      else if (id == "orx32")      push_instr(orx32, offset, ty, id, line, col);
      else if (id == "orx64")      push_instr(orx64, offset, ty, id, line, col);
      else if (id == "xorx16")     push_instr(xorx16, offset, ty, id, line, col);
      else if (id == "xorx32")     push_instr(xorx32, offset, ty, id, line, col);
      else if (id == "xorx64")     push_instr(xorx64, offset, ty, id, line, col);
      else if (id == "addfx16")    push_instr(addfx16, offset, ty, id, line, col);
      else if (id == "addfx32")    push_instr(addfx32, offset, ty, id, line, col);
      else if (id == "addfx64")    push_instr(addfx64, offset, ty, id, line, col);
      else if (id == "andfx16")    push_instr(andfx16, offset, ty, id, line, col);
      else if (id == "andfx32")    push_instr(andfx32, offset, ty, id, line, col);
      else if (id == "andfx64")    push_instr(andfx64, offset, ty, id, line, col);
      else if (id == "orfx16")     push_instr(orfx16, offset, ty, id, line, col);
      else if (id == "orfx32")     push_instr(orfx32, offset, ty, id, line, col);
      else if (id == "orfx64")     push_instr(orfx64, offset, ty, id, line, col);
      else if (id == "xorfx16")    push_instr(xorfx16, offset, ty, id, line, col);
      else if (id == "xorfx32")    push_instr(xorfx32, offset, ty, id, line, col);
      else if (id == "xorfx64")    push_instr(xorfx64, offset, ty, id, line, col);
      else if (id == "xchgx16")    push_instr(xchgx16, offset, ty, id, line, col);
      else if (id == "xchgx32")    push_instr(xchgx32, offset, ty, id, line, col);
      else if (id == "xchgx64")    push_instr(xchgx64, offset, ty, id, line, col);
      else if (id == "cmpxchgx16") push_instr(cmpxchgx16, offset, ty, id, line, col);
      else if (id == "cmpxchgx32") push_instr(cmpxchgx32, offset, ty, id, line, col);
      else if (id == "cmpxchgx64") push_instr(cmpxchgx64, offset, ty, id, line, col);
      else if (id == "ldmapfd")    push_instr(ldmapfd, offset, ty, id, line, col);
      else if (id == "ld64")       push_instr(ld64, offset, ty, id, line, col);
      else if (id == "ldabs8")     push_instr(ldabs8, offset, ty, id, line, col);
      else if (id == "ldabs16")    push_instr(ldabs16, offset, ty, id, line, col);
      else if (id == "ldabs32")    push_instr(ldabs32, offset, ty, id, line, col);
      else if (id == "ldabs64")    push_instr(ldabs64, offset, ty, id, line, col);
      else if (id == "ldind8")     push_instr(ldind8, offset, ty, id, line, col);
      else if (id == "ldind16")    push_instr(ldind16, offset, ty, id, line, col);
      else if (id == "ldind32")    push_instr(ldind32, offset, ty, id, line, col);
      else if (id == "ldind64")    push_instr(ldind64, offset, ty, id, line, col);
      else if (id == "ldx8")       push_instr(ldx8, offset, ty, id, line, col);
      else if (id == "ldx16")      push_instr(ldx16, offset, ty, id, line, col);
      else if (id == "ldx32")      push_instr(ldx32, offset, ty, id, line, col);
      else if (id == "ldx64")      push_instr(ldx64, offset, ty, id, line, col);
      else if (id == "st8")        push_instr(st8, offset, ty, id, line, col);
      else if (id == "st16")       push_instr(st16, offset, ty, id, line, col);
      else if (id == "st32")       push_instr(st32, offset, ty, id, line, col);
      else if (id == "st64")       push_instr(st64, offset, ty, id, line, col);
      else if (id == "stx8")       push_instr(stx8, offset, ty, id, line, col);
      else if (id == "stx16")      push_instr(stx16, offset, ty, id, line, col);
      else if (id == "stx32")      push_instr(stx32, offset, ty, id, line, col);
      else if (id == "stx64")      push_instr(stx64, offset, ty, id, line, col);
      else if (id == "stxx8")      push_instr(stxx8, offset, ty, id, line, col);
      else if (id == "stxx16")     push_instr(stxx16, offset, ty, id, line, col);
      else if (id == "stxx32")     push_instr(stxx32, offset, ty, id, line, col);
      else if (id == "stxx64")     push_instr(stxx64, offset, ty, id, line, col);
      else if (id == "ja")         push_instr(ja, offset, ty, id, line, col);
      else if (id == "jeq")        push_instr(jeq, offset, ty, id, line, col);
      else if (id == "jgt")        push_instr(jgt, offset, ty, id, line, col);
      else if (id == "jge")        push_instr(jge, offset, ty, id, line, col);
      else if (id == "jlt")        push_instr(jlt, offset, ty, id, line, col);
      else if (id == "jle")        push_instr(jle, offset, ty, id, line, col);
      else if (id == "jset")       push_instr(jset, offset, ty, id, line, col);
      else if (id == "jne")        push_instr(jne, offset, ty, id, line, col);
      else if (id == "jsgt")       push_instr(jsgt, offset, ty, id, line, col);
      else if (id == "jsge")       push_instr(jsge, offset, ty, id, line, col);
      else if (id == "jslt")       push_instr(jslt, offset, ty, id, line, col);
      else if (id == "jsle")       push_instr(jsle, offset, ty, id, line, col);
      else if (id == "call")       push_instr(call, offset, ty, id, line, col);
      else if (id == "rel")        push_instr(rel, offset, ty, id, line, col);
      else if (id == "exit")       push_instr(exit_ins, offset, ty, id, line, col);
      else if (id == "jeq32")      push_instr(jeq32, offset, ty, id, line, col);
      else if (id == "jgt32")      push_instr(jgt32, offset, ty, id, line, col);
      else if (id == "jge32")      push_instr(jge32, offset, ty, id, line, col);
      else if (id == "jlt32")      push_instr(jlt32, offset, ty, id, line, col);
      else if (id == "jle32")      push_instr(jle32, offset, ty, id, line, col);
      else if (id == "jset32")     push_instr(jset32, offset, ty, id, line, col);
      else if (id == "jne32")      push_instr(jne32, offset, ty, id, line, col);
      else if (id == "jsgt32")     push_instr(jsgt32, offset, ty, id, line, col);
      else if (id == "jsge32")     push_instr(jsge32, offset, ty, id, line, col);
      else if (id == "jslt32")     push_instr(jslt32, offset, ty, id, line, col);
      else if (id == "jsle32")     push_instr(jsle32, offset, ty, id, line, col);
      else if (id == "zext")       push_instr(zext, offset, ty, id, line, col);
    }
    /* Variables */
    else if (id == "var")
      push_var(i, id, line, col);
    /* Registers */
    else if (ty == reg)
      push_reg(ty, id, line, col);
    /* Immediates */
    else if (ty == imm)
      push_imm(i, line, col);
    /* Directives */
    else if (ty == direc)
      ;
    /* Identifiers */
    else if (ty == ident)
      push_id(i, id, line, col);
    else
      parse_err(line, col, id, "unexpected symbol ``"+id+"``");
  }

}
