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

template <typename T>
static inline void push_instr(uint& offset, Symbol sym, ident_t id,
                              uint line, uint col) {
  T ins;
  ins.off = ++offset;
  absyn_tree.push_back({ins, sym, id, line, col});
}

static inline void push_reg(Symbol sym, ident_t id, uint line, uint col) {
  struct regs r;
  r.reg = det_reg_val(id);
  absyn_tree.push_back({r, sym, id, line, col});
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
  Symbol type = symtab[idx].type;
  ident_t id  = symtab[idx].id;
  struct imm_int i;

  if (type == ident)
    if (is_hex(vname_val(id)))
      i.val = std::stoi(vname_val(id), 0, 16);
    else
      i.val = std::stoi(vname_val(id));
  else if (type == imm)
    if (is_hex(id))
      i.val = std::stoi(id, 0, 16);
    else
      i.val = std::stoi(id);
  else
    parse_err(line, col, id, "not an immediate");

  absyn_tree.push_back({i, imm, std::to_string(i.val), line, col});
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
  Symbol sym;
  ident_t id;
  uint line, col;

  for (uint i=0; i < symtab.size(); i++) {

    entry = symtab[i];
    id    = entry.id;
    sym   = entry.type;
    line  = entry.line;
    col   = entry.col;

    /* Instructions */
    if (sym == instr) {
      if (id == "add")
        push_instr<struct add>(offset, sym, id, line, col);
      else if (id == "sub")
        push_instr<struct sub>(offset, sym, id, line, col);
      else if (id == "mul")
        push_instr<struct mul>(offset, sym, id, line, col);
      else if (id == "div")
        push_instr<struct div_ins>(offset, sym, id, line, col);
      else if (id == "or")
        push_instr<struct or_ins>(offset, sym, id, line, col);
      else if (id == "and")
        push_instr<struct and_ins>(offset, sym, id, line, col);
      else if (id == "lsh")
        push_instr<struct lsh>(offset, sym, id, line, col);
      else if (id == "rsh")
        push_instr<struct rsh>(offset, sym, id, line, col);
      else if (id == "neg")
        push_instr<struct neg>(offset, sym, id, line, col);
      else if (id == "mod")
        push_instr<struct mod>(offset, sym, id, line, col);
      else if (id == "xor")
        push_instr<struct xor_ins>(offset, sym, id, line, col);
      else if (id == "mov")
        push_instr<struct mov>(offset, sym, id, line, col);
      else if (id == "arsh")
        push_instr<struct arsh>(offset, sym, id, line, col);
      else if (id == "add32")
        push_instr<struct add32>(offset, sym, id, line, col);
      else if (id == "sub32")
        push_instr<struct sub32>(offset, sym, id, line, col);
      else if (id == "mul32")
        push_instr<struct mul32>(offset, sym, id, line, col);
      else if (id == "div32")
        push_instr<struct div32>(offset, sym, id, line, col);
      else if (id == "or32")
        push_instr<struct or32>(offset, sym, id, line, col);
      else if (id == "and32")
        push_instr<struct and32>(offset, sym, id, line, col);
      else if (id == "lsh32")
        push_instr<struct lsh32>(offset, sym, id, line, col);
      else if (id == "rsh32")
        push_instr<struct rsh32>(offset, sym, id, line, col);
      else if (id == "rsh32")
        push_instr<struct rsh32>(offset, sym, id, line, col);
      else if (id == "neg32")
        push_instr<struct neg32>(offset, sym, id, line, col);
      else if (id == "mod32")
        push_instr<struct mod32>(offset, sym, id, line, col);
      else if (id == "xor32")
        push_instr<struct xor32>(offset, sym, id, line, col);
      else if (id == "mov32")
        push_instr<struct mov32>(offset, sym, id, line, col);
      else if (id == "arsh32")
        push_instr<struct arsh32>(offset, sym, id, line, col);
      else if (id == "le16")
        push_instr<struct le16>(offset, sym, id, line, col);
      else if (id == "le32")
        push_instr<struct le32>(offset, sym, id, line, col);
      else if (id == "le64")
        push_instr<struct le64>(offset, sym, id, line, col);
      else if (id == "be16")
        push_instr<struct be16>(offset, sym, id, line, col);
      else if (id == "be32")
        push_instr<struct be32>(offset, sym, id, line, col);
      else if (id == "be64")
        push_instr<struct be64>(offset, sym, id, line, col);
      else if (id == "addx16")
        push_instr<struct addx16>(offset, sym, id, line, col);
      else if (id == "addx32")
        push_instr<struct addx32>(offset, sym, id, line, col);
      else if (id == "addx64")
        push_instr<struct addx64>(offset, sym, id, line, col);
      else if (id == "andx16")
        push_instr<struct andx16>(offset, sym, id, line, col);
      else if (id == "andx32")
        push_instr<struct andx32>(offset, sym, id, line, col);
      else if (id == "andx64")
        push_instr<struct andx64>(offset, sym, id, line, col);
      else if (id == "orx16")
        push_instr<struct orx16>(offset, sym, id, line, col);
      else if (id == "orx32")
        push_instr<struct orx32>(offset, sym, id, line, col);
      else if (id == "orx64")
        push_instr<struct orx64>(offset, sym, id, line, col);
      else if (id == "xorx16")
        push_instr<struct xorx16>(offset, sym, id, line, col);
      else if (id == "xorx32")
        push_instr<struct xorx32>(offset, sym, id, line, col);
      else if (id == "xorx64")
        push_instr<struct xorx64>(offset, sym, id, line, col);
      else if (id == "addfx16")
        push_instr<struct addfx16>(offset, sym, id, line, col);
      else if (id == "addfx32")
        push_instr<struct addfx32>(offset, sym, id, line, col);
      else if (id == "addfx64")
        push_instr<struct addfx64>(offset, sym, id, line, col);
      else if (id == "andfx16")
        push_instr<struct andfx16>(offset, sym, id, line, col);
      else if (id == "andfx32")
        push_instr<struct andfx32>(offset, sym, id, line, col);
      else if (id == "andfx64")
        push_instr<struct andfx64>(offset, sym, id, line, col);
      else if (id == "orfx16")
        push_instr<struct orfx16>(offset, sym, id, line, col);
      else if (id == "orfx32")
        push_instr<struct orfx32>(offset, sym, id, line, col);
      else if (id == "orfx64")
        push_instr<struct orfx64>(offset, sym, id, line, col);
      else if (id == "xorfx16")
        push_instr<struct xorfx16>(offset, sym, id, line, col);
      else if (id == "xorfx32")
        push_instr<struct xorfx32>(offset, sym, id, line, col);
      else if (id == "xorfx64")
        push_instr<struct xorfx64>(offset, sym, id, line, col);
      else if (id == "xchgx16")
        push_instr<struct xchgx16>(offset, sym, id, line, col);
      else if (id == "xchgx32")
        push_instr<struct xchgx32>(offset, sym, id, line, col);
      else if (id == "xchgx64")
        push_instr<struct xchgx64>(offset, sym, id, line, col);
      else if (id == "cmpxchgx16")
        push_instr<struct cmpxchgx16>(offset, sym, id, line, col);
      else if (id == "cmpxchgx32")
        push_instr<struct cmpxchgx32>(offset, sym, id, line, col);
      else if (id == "cmpxchgx64")
        push_instr<struct cmpxchgx64>(offset, sym, id, line, col);
      else if (id == "ldmapfd")
        push_instr<struct ldmapfd>(offset, sym, id, line, col);
      else if (id == "ld64")
        push_instr<struct ld64>(offset, sym, id, line, col);
      else if (id == "ldabs8")
        push_instr<struct ldabs8>(offset, sym, id, line, col);
      else if (id == "ldabs16")
        push_instr<struct ldabs16>(offset, sym, id, line, col);
      else if (id == "ldabs32")
        push_instr<struct ldabs32>(offset, sym, id, line, col);
      else if (id == "ldabs64")
        push_instr<struct ldabs64>(offset, sym, id, line, col);
      else if (id == "ldind8")
        push_instr<struct ldind8>(offset, sym, id, line, col);
      else if (id == "ldind16")
        push_instr<struct ldind16>(offset, sym, id, line, col);
      else if (id == "ldind32")
        push_instr<struct ldind32>(offset, sym, id, line, col);
      else if (id == "ldind64")
        push_instr<struct ldind64>(offset, sym, id, line, col);
      else if (id == "ldx8")
        push_instr<struct ldx8>(offset, sym, id, line, col);
      else if (id == "ldx16")
        push_instr<struct ldx16>(offset, sym, id, line, col);
      else if (id == "ldx32")
        push_instr<struct ldx32>(offset, sym, id, line, col);
      else if (id == "ldx64")
        push_instr<struct ldx64>(offset, sym, id, line, col);
      else if (id == "st8")
        push_instr<struct st8>(offset, sym, id, line, col);
      else if (id == "st16")
        push_instr<struct st16>(offset, sym, id, line, col);
      else if (id == "st32")
        push_instr<struct st32>(offset, sym, id, line, col);
      else if (id == "st64")
        push_instr<struct st64>(offset, sym, id, line, col);
      else if (id == "stx8")
        push_instr<struct stx8>(offset, sym, id, line, col);
      else if (id == "stx16")
        push_instr<struct stx16>(offset, sym, id, line, col);
      else if (id == "stx32")
        push_instr<struct stx32>(offset, sym, id, line, col);
      else if (id == "stx64")
        push_instr<struct stx64>(offset, sym, id, line, col);
      else if (id == "stxx8")
        push_instr<struct stxx8>(offset, sym, id, line, col);
      else if (id == "stxx16")
        push_instr<struct stxx16>(offset, sym, id, line, col);
      else if (id == "stxx32")
        push_instr<struct stxx32>(offset, sym, id, line, col);
      else if (id == "stxx64")
        push_instr<struct stxx64>(offset, sym, id, line, col);
      else if (id == "ja")
        push_instr<struct ja>(offset, sym, id, line, col);
      else if (id == "jeq")
        push_instr<struct jeq>(offset, sym, id, line, col);
      else if (id == "jgt")
        push_instr<struct jgt>(offset, sym, id, line, col);
      else if (id == "jge")
        push_instr<struct jge>(offset, sym, id, line, col);
      else if (id == "jlt")
        push_instr<struct jlt>(offset, sym, id, line, col);
      else if (id == "jle")
        push_instr<struct jle>(offset, sym, id, line, col);
      else if (id == "jset")
        push_instr<struct jset>(offset, sym, id, line, col);
      else if (id == "jne")
        push_instr<struct jne>(offset, sym, id, line, col);
      else if (id == "jsgt")
        push_instr<struct jsgt>(offset, sym, id, line, col);
      else if (id == "jsge")
        push_instr<struct jsge>(offset, sym, id, line, col);
      else if (id == "jslt")
        push_instr<struct jslt>(offset, sym, id, line, col);
      else if (id == "jsle")
        push_instr<struct jsle>(offset, sym, id, line, col);
      else if (id == "call")
        push_instr<struct call>(offset, sym, id, line, col);
      else if (id == "rel")
        push_instr<struct rel>(offset, sym, id, line, col);
      else if (id == "exit")
        push_instr<struct exit_ins>(offset, sym, id, line, col);
      else if (id == "jeq32")
        push_instr<struct jeq32>(offset, sym, id, line, col);
      else if (id == "jgt32")
        push_instr<struct jgt32>(offset, sym, id, line, col);
      else if (id == "jge32")
        push_instr<struct jge32>(offset, sym, id, line, col);
      else if (id == "jlt32")
        push_instr<struct jlt32>(offset, sym, id, line, col);
      else if (id == "jle32")
        push_instr<struct jle32>(offset, sym, id, line, col);
      else if (id == "jset32")
        push_instr<struct jset32>(offset, sym, id, line, col);
      else if (id == "jne32")
        push_instr<struct jne32>(offset, sym, id, line, col);
      else if (id == "jsgt32")
        push_instr<struct jsgt32>(offset, sym, id, line, col);
      else if (id == "jsge32")
        push_instr<struct jsge32>(offset, sym, id, line, col);
      else if (id == "jslt32")
        push_instr<struct jslt32>(offset, sym, id, line, col);
      else if (id == "jsle32")
        push_instr<struct jsle32>(offset, sym, id, line, col);
      else if (id == "zext")
        push_instr<struct zext>(offset, sym, id, line, col);
    }
    /* Variables */
    else if (id == "var")
      push_var(i, id, line, col);
    /* Registers */
    else if (sym == reg)
      push_reg(sym, id, line, col);
    /* Immediates */
    else if (sym == imm)
      push_imm(i, line, col);
    /* Directives */
    else if (sym == direc)
      ;
    /* Identifiers */
    else if (sym == ident)
      push_id(i, id, line, col);
    else
      parse_err(line, col, id, "unexpected symbol ``"+id+"``");
  }

}
