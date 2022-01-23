#include "parser.h"
#include <algorithm>

#define parse_err(line, col, id, msg) \
  (error(line, ":", col, ": parse error: ", msg, err_getline(id, line, col)))

std::vector<symtab_t> symtab;

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

static inline bool is_value(std::string s) {
  return (is_number(s) || is_hex(s) || is_decimal(s) || is_negative(s));
}

static inline bool is_whitespace(std::string s) {
  return std::all_of(s.begin(), s.end(), isspace);
}

static inline bool malformed(std::string s) {
  for (int c : s)
    if (c < 1)
      return true;
  return false;
}

static inline bool is_reg(ident_t id) {
  for (ident_t r : registers)
    if (r == id)
      return true;
  return false;
}

static inline bool is_instr(ident_t id) {
  for (ident_t ins : instructions)
    if (ins == id)
      return true;
  return false;
}

size_t offset = 0, col = 1, line = 1;
ident_t tok;

static inline symtab_t lookup_symtab(ident_t id) {
  for (symtab_t e : symtab)
    if (e.id == id)
      return e;
  error("``", id, "`` is not a directive");
  return {"", 0};
}

static inline bool is_directive(ident_t id) {
  for (symtab_t e : symtab)
    if (e.id == id)
      return true;
  return false;
}

static inline void push_reg() {
  ast.push_back({regs, reg, tok, 0, 0, line, col});
}

static inline void push_instr(Node node, size_t arg_num) {
  ast.push_back({node, instr, tok, ++offset, arg_num, line, col});
}

static inline void push_ident() {
  ast.push_back({dirs, ident, tok, 0, 0, line, col});
}

static inline void instruction(ident_t id = tok) {
  if      (id == "add")        push_instr(add,        2);
  else if (id == "sub")        push_instr(sub,        2);
  else if (id == "mul")        push_instr(mul,        2);
  else if (id == "div")        push_instr(div_ins,    2);
  else if (id == "or")         push_instr(or_ins,     2);
  else if (id == "and")        push_instr(and_ins,    2);
  else if (id == "lsh")        push_instr(lsh,        2);
  else if (id == "rsh")        push_instr(rsh,        2);
  else if (id == "neg")        push_instr(neg,        1);
  else if (id == "mod")        push_instr(mod,        2);
  else if (id == "xor")        push_instr(xor_ins,    2);
  else if (id == "mov")        push_instr(mov,        2);
  else if (id == "arsh")       push_instr(arsh,       2);
  else if (id == "add32")      push_instr(add32,      2);
  else if (id == "sub32")      push_instr(sub32,      2);
  else if (id == "mul32")      push_instr(mul32,      2);
  else if (id == "div32")      push_instr(div32,      2);
  else if (id == "or32")       push_instr(or32,       2);
  else if (id == "and32")      push_instr(and32,      2);
  else if (id == "lsh32")      push_instr(lsh32,      2);
  else if (id == "rsh32")      push_instr(rsh32,      2);
  else if (id == "neg32")      push_instr(neg32,      1);
  else if (id == "mod32")      push_instr(mod32,      2);
  else if (id == "xor32")      push_instr(xor32,      2);
  else if (id == "mov32")      push_instr(mov32,      2);
  else if (id == "arsh32")     push_instr(arsh32,     2);
  else if (id == "le16")       push_instr(le16,       1);
  else if (id == "le32")       push_instr(le32,       1);
  else if (id == "le64")       push_instr(le64,       1);
  else if (id == "be16")       push_instr(be16,       1);
  else if (id == "be32")       push_instr(be32,       1);
  else if (id == "be64")       push_instr(be64,       1);
  else if (id == "addx16")     push_instr(addx16,     3);
  else if (id == "addx32")     push_instr(addx32,     3);
  else if (id == "addx64")     push_instr(addx64,     3);
  else if (id == "andx16")     push_instr(andx16,     3);
  else if (id == "andx32")     push_instr(andx32,     3);
  else if (id == "andx64")     push_instr(andx64,     3);
  else if (id == "orx16")      push_instr(orx16,      3);
  else if (id == "orx32")      push_instr(orx32,      3);
  else if (id == "orx64")      push_instr(orx64,      3);
  else if (id == "xorx16")     push_instr(xorx16,     3);
  else if (id == "xorx32")     push_instr(xorx32,     3);
  else if (id == "xorx64")     push_instr(xorx64,     3);
  else if (id == "addfx16")    push_instr(addfx16,    3);
  else if (id == "addfx32")    push_instr(addfx32,    3);
  else if (id == "addfx64")    push_instr(addfx64,    3);
  else if (id == "andfx16")    push_instr(andfx16,    3);
  else if (id == "andfx32")    push_instr(andfx32,    3);
  else if (id == "andfx64")    push_instr(andfx64,    3);
  else if (id == "orfx16")     push_instr(orfx16,     3);
  else if (id == "orfx32")     push_instr(orfx32,     3);
  else if (id == "orfx64")     push_instr(orfx64,     3);
  else if (id == "xorfx16")    push_instr(xorfx16,    3);
  else if (id == "xorfx32")    push_instr(xorfx32,    3);
  else if (id == "xorfx64")    push_instr(xorfx64,    3);
  else if (id == "xchgx16")    push_instr(xchgx16,    3);
  else if (id == "xchgx32")    push_instr(xchgx32,    3);
  else if (id == "xchgx64")    push_instr(xchgx64,    3);
  else if (id == "cmpxchgx16") push_instr(cmpxchgx16, 3);
  else if (id == "cmpxchgx32") push_instr(cmpxchgx32, 3);
  else if (id == "cmpxchgx64") push_instr(cmpxchgx64, 3);
  else if (id == "ldmapfd")    push_instr(ldmapfd,    2);
  else if (id == "ld64")       push_instr(ld64,       2);
  else if (id == "ldabs8")     push_instr(ldabs8,     1);
  else if (id == "ldabs16")    push_instr(ldabs16,    1);
  else if (id == "ldabs32")    push_instr(ldabs32,    1);
  else if (id == "ldabs64")    push_instr(ldabs64,    1);
  else if (id == "ldind8")     push_instr(ldind8,     2);
  else if (id == "ldind16")    push_instr(ldind16,    2);
  else if (id == "ldind32")    push_instr(ldind32,    2);
  else if (id == "ldind64")    push_instr(ldind64,    2);
  else if (id == "ldx8")       push_instr(ldx8,       3);
  else if (id == "ldx16")      push_instr(ldx16,      3);
  else if (id == "ldx32")      push_instr(ldx32,      3);
  else if (id == "ldx64")      push_instr(ldx64,      3);
  else if (id == "st8")        push_instr(st8,        3);
  else if (id == "st16")       push_instr(st16,       3);
  else if (id == "st32")       push_instr(st32,       3);
  else if (id == "st64")       push_instr(st64,       3);
  else if (id == "stx8")       push_instr(stx8,       3);
  else if (id == "stx16")      push_instr(stx16,      3);
  else if (id == "stx32")      push_instr(stx32,      3);
  else if (id == "stx64")      push_instr(stx64,      3);
  else if (id == "stxx8")      push_instr(stxx8,      3);
  else if (id == "stxx16")     push_instr(stxx16,     3);
  else if (id == "stxx32")     push_instr(stxx32,     3);
  else if (id == "stxx64")     push_instr(stxx64,     3);
  else if (id == "ja")         push_instr(ja,         1);
  else if (id == "jeq")        push_instr(jeq,        3);
  else if (id == "jgt")        push_instr(jgt,        3);
  else if (id == "jge")        push_instr(jge,        3);
  else if (id == "jlt")        push_instr(jlt,        3);
  else if (id == "jle")        push_instr(jle,        3);
  else if (id == "jset")       push_instr(jset,       3);
  else if (id == "jne")        push_instr(jne,        3);
  else if (id == "jsgt")       push_instr(jsgt,       3);
  else if (id == "jsge")       push_instr(jsge,       3);
  else if (id == "jslt")       push_instr(jslt,       3);
  else if (id == "jsle")       push_instr(jsle,       3);
  else if (id == "call")       push_instr(call,       1);
  else if (id == "rel")        push_instr(rel,        1);
  else if (id == "exit")       push_instr(exit_ins,   0);
  else if (id == "jeq32")      push_instr(jeq32,      3);
  else if (id == "jgt32")      push_instr(jgt32,      3);
  else if (id == "jge32")      push_instr(jge32,      3);
  else if (id == "jlt32")      push_instr(jlt32,      3);
  else if (id == "jle32")      push_instr(jle32,      3);
  else if (id == "jset32")     push_instr(jset32,     3);
  else if (id == "jne32")      push_instr(jne32,      3);
  else if (id == "jsgt32")     push_instr(jsgt32,     3);
  else if (id == "jsge32")     push_instr(jsge32,     3);
  else if (id == "jslt32")     push_instr(jslt32,     3);
  else if (id == "jsle32")     push_instr(jsle32,     3);
  else if (id == "zext")       push_instr(zext,       1);
}

const char *expr;

static inline void align() {
  if (*expr == '\n') {
    line++;
    col = 0;
  }
  col++;
}

static inline char sym() {
  return *expr;
}

static inline char next_sym() {
  align();
  return *expr++;
}

static inline void clear() {
  tok.clear();
}

template<typename T1, typename ... T>
static inline bool some_eq(T1 &&v1, T && ... v) {
    return ((v1 == v) || ...);
}

static inline bool seperator() {
  return some_eq(sym(), ';', ':', '\0') || isspace(sym());
}

static inline void comment() {
  while (next_sym() != '\n')
    ;;
}

static inline void number() {
  int i;
  if (is_hex(tok))
    i = stoi_w(tok, 0, 16);
  else
    i = stoi_w(tok);
  ast.push_back({imm_int, imm, std::to_string(i), 0, 0, line, col});
}

static inline void directive() {
  if (is_value(tok) || is_reg(tok) || is_instr(tok))
    parse_err(line, col, tok, "directive: ``"+tok+"`` cannot be a number or keyword");

  if (is_directive(tok))
    parse_err(line, col, tok, "multiple directive definitions of ``"+tok+"``");

  if (offset)
    symtab.push_back({tok, offset});
  else
    symtab.push_back({tok, 1});
}

static inline void identifier() {
  push_ident();
}

static inline void assembly() {
  if (is_instr(tok))
    instruction();
  else if (is_reg(tok))
    push_reg();
  else
    identifier();
}

static inline void statement() {
  if (sym() == '\0')
    return;
  else if (sym() == ';')
    comment();

  while (!seperator())
    tok += next_sym();

  if (sym() == ':')
    directive();
  else if (is_value(tok))
    number();
  else if (!is_whitespace(tok) && !malformed(tok))
    assembly();

  if (sym() == ';')
    comment();
  else
    next_sym();
  
  clear();
  statement();
}

static inline void transform() {
  for (ast_t &n : ast) {
    if (n.type == ident) {
      if (is_directive(n.id)) {
        n.node_v = imm_int;
        n.type   = imm;
        n.id     = std::to_string(lookup_symtab(n.id).off);
      }
      else
        parse_err(n.line, n.col, n.id, "undefined identifier: "+n.id);
    }
  }
}

void parser(void) {
  expr = bytecode.c_str();
  statement();
  transform();

  if (!offset)
    error(line, ":", col, ": parse error: expected at least one instruction");
}
