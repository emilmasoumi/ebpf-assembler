#include <stddef.h>
#include <stdint.h>
#include <string>
#include <iomanip>
#include <string.h>
#include "utils.hpp"

#ifndef AST_H
#define AST_H

#define OPERANDS  3
#define MAX_INSNS 1000000

#define FST 0
#define SND 1
#define TRD 2
#define FRT 3

#define ASIZE ast.size()
#define PUSH  ast.push_back

typedef enum {Instruction, Immediate, Register, Label, Reference, Empty} Type;

typedef enum {r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10} Regs;

typedef enum {
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
  div_,

  /* or dst src */
  /* or dst imm */
  or_,

  /* and dst src */
  /* and dst imm */
  and_,

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
  xor_,

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
  exit_,

  /* jeq32 dst imm off */
  /* jeq32 dst src off */
  jeq32,

  /* jgt32 dst imm off */
  /* jgt32 dst src off */
  jgt32,

  /* jge32 dst imm off */
  /* jge32 dst src off */
  jge32,

  /* jlt32 dst imm off */
  /* jlt32 dst src off */
  jlt32,

  /* jle32 dst imm off */
  /* jle32 dst src off */
  jle32,

  /* jset32 dst imm off */
  /* jset32 dst src off */
  jset32,

  /* jne32 dst imm off */
  /* jne32 dst src off */
  jne32,

  /* jsgt32 dst imm off */
  /* jsgt32 dst src off */
  jsgt32,

  /* jsge32 dst imm off */
  /* jsge32 dst src off */
  jsge32,

  /* jslt32 dst imm off */
  /* jslt32 dst src off */
  jslt32,

  /* jsle32 dst imm off */
  /* jsle32 dst src off */
  jsle32,

  /* zext dst */
  zext,
} ISA;

struct Pos {
  Nat line;
  Nat col;
};

struct Imm {
  Int32 val;
  Pos   pos;
};

struct Reg {
  Regs reg;
  Pos  pos;
};

struct Lab {
  Id  lname;
  Nat off;
  Pos pos;
};

struct Ref {
  Id  id;
  Pos pos;
};

struct Ins {
  struct {U(Reg reg; Imm imm; Ref var;); Type ty = Empty;} ops[OPERANDS];
  ISA  ins;
  Pos  pos;
};

struct Stat {
  U(Ins ins; Lab lab;);
  Type ty;
};

typedef Vector<Stat> AST;

extern AST ast;
extern Str bytecode;

TUPLE(RegsL, Id s; Regs reg;);
TUPLE(InsL,  Id s; ISA  ins;);

static const RegsL registers[] =
  {{"r0", r0}, {"r1", r1}, {"r2", r2}, {"r3", r3}, {"r4",  r4},  {"r5", r5},
   {"r6", r6}, {"r7", r7}, {"r8", r8}, {"r9", r9}, {"r10", r10}};
static const InsL instructions[] =
  {{"add", add},  {"sub", sub}, {"mul",  mul}, {"div", div_}, {"or",  or_},
   {"and", and_}, {"lsh", lsh}, {"rsh",  rsh}, {"neg", neg},  {"mod", mod},
   {"xor", xor_}, {"mov", mov}, {"arsh", arsh},
   {"add32",  add32}, {"sub32", sub32}, {"mul32", mul32}, {"div32", div32},
   {"or32",   or32},  {"and32", and32}, {"lsh32", lsh32}, {"rsh32", rsh32},
   {"neg32",  neg32}, {"mod32", mod32}, {"xor32", xor32}, {"mov32", mov32},
   {"arsh32", arsh32},
   {"le16", le16}, {"le32", le32}, {"le64", le64}, {"be16", be16},
   {"be32", be32}, {"be64", be64},
   {"addx16",  addx16},  {"addx32",  addx32},  {"addx64",  addx64},
   {"andx16",  andx16},  {"andx32",  andx32},  {"andx64",  andx64},
   {"orx16",   orx16},   {"orx32",   orx32},   {"orx64",   orx64},
   {"xorx16",  xorx16},  {"xorx32",  xorx32},  {"xorx64",  xorx64},
   {"addfx16", addfx16}, {"addfx32", addfx32}, {"addfx64", addfx64},
   {"andfx16", andfx16}, {"andfx32", andfx32}, {"andfx64", andfx64},
   {"orfx16",  orfx16},  {"orfx32",  orfx32},  {"orfx64",  orfx64},
   {"xorfx16", xorfx16}, {"xorfx32", xorfx32}, {"xorfx64", xorfx64},
   {"xchgx16", xchgx16}, {"xchgx32", xchgx32}, {"xchgx64", xchgx64},
   {"cmpxchgx16", cmpxchgx16}, {"cmpxchgx32", cmpxchgx32},
   {"cmpxchgx64", cmpxchgx64},
   {"ldmapfd", ldmapfd}, {"ld64",    ld64},
   {"ldabs8",  ldabs8},  {"ldabs16", ldabs16}, {"ldabs32", ldabs32},
   {"ldabs64", ldabs64},
   {"ldind8",  ldind8}, {"ldind16", ldind16}, {"ldind32", ldind32},
   {"ldind64", ldind64},
   {"ldx8",  ldx8},  {"ldx16",  ldx16},  {"ldx32",  ldx32},  {"ldx64",  ldx64},
   {"st8",   st8},   {"st16",   st16},   {"st32",   st32},   {"st64",   st64},
   {"stx8",  stx8},  {"stx16",  stx16},  {"stx32",  stx32},  {"stx64",  stx64},
   {"stxx8", stxx8}, {"stxx16", stxx16}, {"stxx32", stxx32}, {"stxx64", stxx64},
   {"ja",   ja},  {"jeq",  jeq}, {"jgt", jgt}, {"jge", jge}, {"jlt", jlt},
   {"jle",  jle}, {"jset", jset},
   {"jne",  jne}, {"jsgt", jsgt}, {"jsge", jsge}, {"jslt", jslt},
   {"jsle", jsle},
   {"call", call}, {"rel", rel}, {"exit", exit_},
   {"jeq32",  jeq32},  {"jgt32",  jgt32},  {"jge32",  jge32},
   {"jlt32",  jlt32},  {"jle32",  jle32},  {"jset32", jset32},
   {"jne32",  jne32},  {"jsgt32", jsgt32}, {"jsge32", jsge32},
   {"jslt32", jslt32}, {"jsle32", jsle32},
   {"zext", zext}};

void dealloc();
void pp_ast();

Id toId(Str);
Id pp_type(Type);
Id pp_reg(Regs);
Id pp_ins(ISA);

Id pp_stat(Nat i = ASIZE - 1);

Stat& stat(Nat i = ASIZE - 1);

ISA&  isa(Nat i = ASIZE - 1);
Ins&  ins(Nat i = ASIZE - 1);
Lab&  lab(Nat i = ASIZE - 1);

Type& type(  Nat i = ASIZE - 1);
Type& optype(Nat i, Nat j = ASIZE - 1);

Imm& imm(Nat i, Nat j = ASIZE - 1);
Reg& reg(Nat i, Nat j = ASIZE - 1);
Ref& ref(Nat i, Nat j = ASIZE - 1);

#endif
