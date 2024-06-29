#include "parser.hpp"
#include <algorithm>

#define SYMBOLS '-', '+', '/', '*', '>', '<', '=',  '|', '&', '%', '(', ')', \
                '{', '}', ',', '.', ':', ';', '#', '\'', '\"'

Id symbols = "- + / * > < = | & % ( ) { } , . : ; # \' \"";

#define ERROR(...) \
  (error(line, ":", col, ": " ERR_STR, __VA_ARGS__, highlight(tok, line, col)))

const char* expr;
Str tok;

Nat offset = 0, col = 1, line = 1;

static inline void check_off() {
  if (offset < 1)
    error(line, ":", col, ": " ERR_STR "expected at least one instruction");
  else if (offset > MAX_INSNS)
    ERROR("instruction limit [", MAX_INSNS, "] exceeded: [", offset, "]");
}

static inline bool is_number(Str s) {
  if (s.size() > 1 && s[0] == '-')
    return (s.find_first_not_of("0123456789", 1) == Str::npos);
  return (!s.empty() && std::all_of(s.begin(), s.end(), ::isdigit));
}

static inline bool is_hex(Str s) {
  if (s.size() > 3 && s[0] == '-')
    return (s.compare(1, 2, "0x") == 0 &&
            s.find_first_not_of("0123456789abcdefABCDEF", 3) == Str::npos);
  return (s.size() > 2 && s.compare(0, 2, "0x") == 0 &&
          s.find_first_not_of("0123456789abcdefABCDEF", 2) == Str::npos);
}

static inline bool is_decimal(Str s) {
  if (s.size() >= 4 && s[0] == '-')
    return (s[1] != '.' && s[s.size()-1] != '.' &&
            std::count(s.begin(), s.end(), '.') == 1 &&
            s.find_first_not_of("0123456789.", 1) == Str::npos);
  return (s.size() >= 3 && s[0] != '.' && s[s.size()-1] != '.' &&
          std::count(s.begin(), s.end(), '.') == 1 &&
          s.find_first_not_of("0123456789.", 0) == Str::npos);
}

static inline bool is_value(Str s) {
  return (is_number(s) || is_hex(s) || is_decimal(s));
}

static inline bool is_whitespace(Str s) {
  return std::all_of(s.begin(), s.end(), isspace);
}

static inline bool malformed(Str s) {
  for (int c : s)
    if (c < 1)
      return true;
  return false;
}

static inline bool is_reg(Str id) {
  for (auto [s, r] : registers)
    if (s == id)
      return true;
  return false;
}

static inline bool is_instr(Str id) {
  for (auto [s, i] : instructions)
    if (s == id)
      return true;
  return false;
}

static inline bool is_label(Str id) {
  for (Stat s : ast)
    if (s.ty == Label && s.lab.lname == id)
      return true;
  return false;
}

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
  while(!some_eq(next_sym(), '\n', '\0'))
    ;;
}

static inline bool has_reserved(Str id) {
  return std::any_of(id.begin(), id.end(),
                     [](unsigned char c) { return some_eq(c, SYMBOLS); });
}

static inline void instruction(Str id = tok) {
  for (auto [s, i] : instructions)
    if (id == s) {
      PUSH(Stat{.ins = Ins{.ins = i, .pos = Pos {line, col}},
                .ty  = Instruction});
      ++offset;
      if (i == ld64 || i == ldmapfd)
        ++offset;
      return;
    }
}

static inline void label() {
  if (is_value(tok) || is_reg(tok) || is_instr(tok))
    ERROR("label: `", tok, "` cannot be a number or keyword");
  if (is_label(tok))
    ERROR("multiple equivalent label definitions of `", tok, "`");
  if (has_reserved(tok))
    ERROR("label: `", tok, "` cannot contain a reserved symbol:", symbols);
  if (tok.empty())
    ERROR("a label identifier cannot be empty");

  PUSH(Stat{.lab = Lab{toId(tok), offset, Pos{line, col}}, .ty = Label});
}

#define CHECK if (ASIZE < 1) { \
  ERROR("undefined referencing");}

#define VALID_OP_PASS(x) CHECK; if (type() != Instruction) { \
  ERROR(#x" cannot be passed to: ", pp_type(type()));}

#define EXCESSIVE_OPS \
  ERROR("too many operands specified: `", tok, "` when passed to: ", \
        pp_stat(), " : ", pp_type(type()));

static inline void imm() {
  Int32 v = is_hex(tok) ? stoi_w(tok, 0, 16) : stoi_w(tok);
  VALID_OP_PASS(immediates);
  for (Nat i = 0; i < OPERANDS; ++i)
    if (optype(i) == Empty) {
      optype(i) = Immediate;
      imm(i)    = {v, Pos{line, col}};
      return;
    }
  EXCESSIVE_OPS
}

static inline void register_() {
  VALID_OP_PASS(registers);
  for (Nat i = 0; i < OPERANDS; ++i) {
    if (optype(i) == Empty) {
      optype(i) = Register;
      for (auto [s, r] : registers) {
        if (tok == s) {
          reg(i) = {r, Pos{line, col}};
          return;
        }
      }
    }
  }
  EXCESSIVE_OPS
}

static inline void identifier() {
  if (has_reserved(tok))
    ERROR("expression: `", tok, "` cannot contain a reserved symbol: ",
          symbols);
  VALID_OP_PASS(identifiers);
  for (Nat i = 0; i < OPERANDS; ++i)
    if (optype(i) == Empty) {
      optype(i) = Reference;
      ref(i)    = Ref{toId(tok), Pos{line, col}};
      return;
    }
  EXCESSIVE_OPS
}

static inline Lab lookup_label(Id id, Pos p) {
  for (Nat i = 0; i < ASIZE; ++i)
    if (type(i) == Label && !strcmp(id, lab(i).lname))
      return lab(i);
  error(p.line, ":", p.col, ": " ERR_STR "undefined identifier: `", id,
        "` in this scope", highlight(id, p.line, p.col));
  return Lab{};
}

static inline void deduce() {
  Ref var;
  Lab lab;
  for (Nat i = 0, pc = 0; i < ASIZE; ++i) {
    if (type(i) != Instruction)
      continue;
    ++pc;
    if (isa(i) == ld64 || isa(i) == ldmapfd)
      ++pc;
    for (Nat j = 0; j < OPERANDS; ++j) {
      if (optype(j, i) == Reference) {
        var = ref(j, i);
        lab = lookup_label(var.id, var.pos);
        delete[] var.id;
        optype(j, i) = Immediate;
        imm(j, i)    = {(Int)lab.off-(Int)pc, var.pos};
      }
    }
  }
}

static inline void assembly() {
  if (is_instr(tok))
    instruction();
  else if (is_reg(tok))
    register_();
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
    label();
  else if (is_value(tok))
    imm();
  else if (!is_whitespace(tok) && !malformed(tok))
    assembly();

  if (sym() == ';')
    comment();
  else
    next_sym();

  clear();
  statement();
}

void parser() {
  expr = bytecode.c_str();

  statement();
  deduce();

  check_off();
}
