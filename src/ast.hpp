#include <ostream>
#include <cstdint>
#include <vector>
#include <iostream>
#include <iomanip>
#include "utils.hpp"

#ifndef AST
#define AST

typedef enum {instr, ident, direc, imm, reg} Type;

typedef enum {
  /* Directives */
  dirs,

  /* Immediates */
  imm_int,
  imm_float,

  /* Registers */
  regs,

  /* Instructions */

  /* add dst src */
  /* add dst imm */
  add,

  /* sub dst src */
  /* sub dst imm */
  sub,

  /* mul dst src */
  /* mul dst imm */
  mul,

  /* div dst src */
  /* div dst imm */
  div_ins,

  /* or dst src */
  /* or dst imm */
  or_ins,

  /* and dst src */
  /* and dst imm */
  and_ins,

  /* lsh dst src */
  /* lsh dst imm */
  lsh,

  /* rsh dst src */
  /* rsh dst imm */
  rsh,

  /* neg dst */
  neg,

  /* mod dst src */
  /* mod dst imm */
  mod,

  /* xor dst src */
  /* xor dst imm */
  xor_ins,

  /* mov dst src */
  /* mov dst imm */
  mov,

  /* arsh dst src */
  /* arsh dst imm */
  arsh,

  /* add32 dst src */
  /* add32 dst imm */
  add32,

  /* sub32 dst src */
  /* sub32 dst imm */
  sub32,

  /* mul32 dst src */
  /* mul32 dst imm */
  mul32,

  /* div32 dst src */
  /* div32 dst imm */
  div32,

  /* or32 dst src */
  /* or32 dst imm */
  or32,

  /* and32 dst src */
  /* and32 dst imm */
  and32,

  /* lsh32 dst src */
  /* lsh32 dst imm */
  lsh32,

  /* rsh32 dst src */
  /* rsh32 dst imm */
  rsh32,

  /* neg32 dst */
  neg32,

  /* mod32 dst src */
  /* mod32 dst imm */
  mod32,

  /* xor32 dst src */
  /* xor32 dst imm */
  xor32,

  /* mov32 dst src */
  /* mov32 dst imm */
  mov32,

  /* arsh32 dst src */
  /* arsh32 dst imm */
  arsh32,

  /* le16 dst */
  le16,

  /* le32 dst */
  le32,

  /* le64 dst */
  le64,

  /* be16 dst */
  be16,

  /* be32 dst */
  be32,

  /* be64 dst */
  be64,

  /* addx16 dst src off */
  addx16,

  /* addx32 dst src off */
  addx32,

  /* addx64 dst src off */
  addx64,

  /* andx16 dst src off */
  andx16,

  /* andx32 dst src off */
  andx32,

  /* andx64 dst src off */
  andx64,

  /* orx16 dst src off */
  orx16,

  /* orx32 dst src off */
  orx32,

  /* orx64 dst src off */
  orx64,

  /* xorx16 dst src off */
  xorx16,

  /* xorx32 dst src off */
  xorx32,

  /* xorx64 dst src off */
  xorx64,

  /* addfx16 dst src off */
  addfx16,

  /* addfx32 dst src off */
  addfx32,

  /* addfx64 dst src off */
  addfx64,

  /* andfx16 dst src off */
  andfx16,

  /* andfx32 dst src off */
  andfx32,

  /* andfx64 dst src off */
  andfx64,

  /* orfx16 dst src off */
  orfx16,

  /* orfx32 dst src off */
  orfx32,

  /* orfx64 dst src off */
  orfx64,

  /* xorfx16 dst src off */
  xorfx16,

  /* xorfx32 dst src off */
  xorfx32,

  /* xorfx64 dst src off */
  xorfx64,

  /* xchgx16 dst src off */
  xchgx16,

  /* xchgx32 dst src off */
  xchgx32,

  /* xchgx64 dst src off */
  xchgx64,

  /* cmpxchgx16 dst src off */
  cmpxchgx16,

  /* cmpxchgx32 dst src off */
  cmpxchgx32,

  /* cmpxchgx64 dst src off */
  cmpxchgx64,

  /* ldmapfd dst imm */
  ldmapfd,

  /* ld64 dst imm */
  ld64,

  /* ldabs8 imm */
  ldabs8,

  /* ldabs16 imm */
  ldabs16,

  /* ldabs32 imm */
  ldabs32,

  /* ldabs64 imm */
  ldabs64,

  /* ldind8 src imm */
  ldind8,

  /* ldind16 src imm */
  ldind16,

  /* ldind32 src imm */
  ldind32,

  /* ldind64 src imm */
  ldind64,

  /* ldx8 dst src off */
  ldx8,

  /* ldx16 dst src off */
  ldx16,

  /* ldx32 dst src off */
  ldx32,

  /* ldx64 dst src off */
  ldx64,

  /* st8 dst off imm */
  st8,

  /* st16 dst off imm */
  st16,

  /* ST32 dst off imm */
  st32,

  /* ST64 dst off imm */
  st64,

  /* stx8 dst off imm */
  stx8,

  /* stx16 dst off imm */
  stx16,

  /* stx32 dst off imm */
  stx32,

  /* stx64 dst off imm */
  stx64,

  /* stxx8 dst off imm */
  stxx8,

  /* stxx16 dst off imm */
  stxx16,

  /* stxx32 dst off imm */
  stxx32,

  /* stxx64 dst off imm */
  stxx64,

  /* ja off */
  ja,

  /* jeq dst imm off */
  /* jeq dst src off */
  jeq,

  /* jgt dst imm off */
  /* jgt dst src off */
  jgt,

  /* jge dst imm off */
  /* jge dst src off */
  jge,

  /* jlt dst imm off */
  /* jlt dst src off */
  jlt,

  /* jle dst imm off */
  /* jle dst src off */
  jle,

  /* jset dst imm off */
  /* jset dst src off */
  jset,

  /* jne dst imm off */
  /* jne dst src off */
  jne,

  /* jsgt dst imm off */
  /* jsgt dst src off */
  jsgt,

  /* jsge dst imm off */
  /* jsge dst src off */
  jsge,

  /* jslt dst imm off */
  /* jslt dst src off */
  jslt,

  /* jsle dst imm off */
  /* jsle dst src off */
  jsle,

  /* call imm */
  call,

  /* rel imm */
  rel,

  /* exit */
  exit_ins,

  /* jeq32 dst imm off */
  /* jeq32  dst src off */
  jeq32,

  /* jgt32 dst imm off */
  /* jgt32  dst src off */
  jgt32,

  /* jge32 dst imm off */
  /* jge32  dst src off */
  jge32,

  /* jlt32 dst imm off */
  /* jlt32  dst src off */
  jlt32,

  /* jle32 dst imm off */
  /* jle32  dst src off */
  jle32,

  /* jset32 dst imm off */
  /* jset32  dst src off */
  jset32,

  /* jne32 dst imm off */
  /* jne32  dst src off */
  jne32,

  /* jsgt32 dst imm off */
  /* jsgt32  dst src off */
  jsgt32,

  /* jsge32 dst imm off */
  /* jsge32  dst src off */
  jsge32,

  /* jslt32 dst imm off */
  /* jslt32  dst src off */
  jslt32,

  /* jsle32 dst imm off */
  /* jsle32  dst src off */
  jsle32,

  /* zext dst */
  zext,

  /* Custom debugging instruction */
  dead_ins
} Node;

typedef std::string ident_t;
typedef size_t line_t;
typedef size_t col_t;

struct ast_t {
  Node    node_v;
  Type    type;
  ident_t id;
  size_t  off;
  size_t  arg_num;
  line_t  line;
  col_t   col;
};

extern std::vector<ast_t> ast;

#define CMP_TYPES(t1, t2) (std::is_same<t1, t2>::value)
#define TYPENAME(e) (typeid(e).name())

#define dealloc_ast() (ast.erase(ast.begin(), ast.end()))

std::string pp_node(Node);
std::string pp_type(Type);
uint get_ops(Node);
uint get_off(Node);
void pp_ast(void);

struct symtab_t {
  std::string id;
  size_t      off;
};

#endif
