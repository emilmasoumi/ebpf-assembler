#include <ostream>
#include <cstdint>
#include <any>

#include "symtab.h"

#ifndef AST
#define AST

struct ast_t {
  std::any node_v;
  Symbol type;
  ident_t id;
  line_t line;
  col_t col;
};

extern std::vector<struct ast_t> absyn_tree;

#define CMP_TYPES(t1, t2) (std::is_same<t1, t2>::value)
#define TYPENAME(e) (typeid(e).name())
/* Compare the subtype of type `any` e with type t */
#define IS_OF_TYPE(e, t) (std::any_cast<t>(&e) != nullptr)

#define dealloc_absyn_tree() \
  (absyn_tree.erase(absyn_tree.begin(), absyn_tree.end()))

int det_reg_val(std::string);
std::string pp_subtype(std::any);
uint get_ops(std::any);
uint get_off(std::any);
std::string pp_type(Symbol);
void pp_ast(void);

/* Variables */
struct var {
  std::string name;
  std::string val;
};

/* Directives */
struct dir {
  std::string name;
  int val;
};

/* Immediates */
struct imm_int {
  int val;
};

struct imm_float {
  float val;
};

/* Registers */
struct regs {
  int reg;
};

/* Instructions */

/* add dst src */
/* add dst imm */
struct add {
  uint off;
  // operand count
  uint ops = 2;
};

/* sub dst src */
/* sub dst imm */
struct sub {
  uint off;
  uint ops = 2;
};

/* mul dst src */
/* mul dst imm */
struct mul {
  uint off;
  uint ops = 2;
};

/* div dst src */
/* div dst imm */
struct div_ins {
  uint off;
  uint ops = 2;
};

/* or dst src */
/* or dst imm */
struct or_ins {
  uint off;
  uint ops = 2;
};

/* and dst src */
/* and dst imm */
struct and_ins {
  uint off;
  uint ops = 2;
};

/* lsh dst src */
/* lsh dst imm */
struct lsh {
  uint off;
  uint ops = 2;
};

/* rsh dst src */
/* rsh dst imm */
struct rsh {
  uint off;
  uint ops = 2;
};

/* neg dst */
struct neg {
  uint off;
  uint ops = 1;
};

/* mod dst src */
/* mod dst imm */
struct mod {
  uint off;
  uint ops = 2;
};

/* xor dst src */
/* xor dst imm */
struct xor_ins {
  uint off;
  uint ops = 2;
};

/* mov dst src */
/* mov dst imm */
struct mov {
  uint off;
  uint ops = 2;
};

/* arsh dst src */
/* arsh dst imm */
struct arsh {
  uint off;
  uint ops = 2;
};

/* add32 dst src */
/* add32 dst imm */
struct add32 {
  uint off;
  uint ops = 2;
};

/* sub32 dst src */
/* sub32 dst imm */
struct sub32 {
  uint off;
  uint ops = 2;
};

/* mul32 dst src */
/* mul32 dst imm */
struct mul32 {
  uint off;
  uint ops = 2;
};

/* div32 dst src */
/* div32 dst imm */
struct div32 {
  uint off;
  uint ops = 2;
};

/* or32 dst src */
/* or32 dst imm */
struct or32 {
  uint off;
  uint ops = 2;
};

/* and32 dst src */
/* and32 dst imm */
struct and32 {
  uint off;
  uint ops = 2;
};

/* lsh32 dst src */
/* lsh32 dst imm */
struct lsh32 {
  uint off;
  uint ops = 2;
};

/* rsh32 dst src */
/* rsh32 dst imm */
struct rsh32 {
  uint off;
  uint ops = 2;
};

/* neg32 dst */
struct neg32 {
  uint off;
  uint ops = 1;
};

/* mod32 dst src */
/* mod32 dst imm */
struct mod32 {
  uint off;
  uint ops = 2;
};

/* xor32 dst src */
/* xor32 dst imm */
struct xor32 {
  uint off;
  uint ops = 2;
};

/* mov32 dst src */
/* mov32 dst imm */
struct mov32 {
  uint off;
  uint ops = 2;
};

/* arsh32 dst src */
/* arsh32 dst imm */
struct arsh32 {
  uint off;
  uint ops = 2;
};

/* le16 dst */
struct le16 {
  uint off;
  uint ops = 1;
};

/* le32 dst */
struct le32 {
  uint off;
  uint ops = 1;
};

/* le64 dst */
struct le64 {
  uint off;
  uint ops = 1;
};

/* be16 dst */
struct be16 {
  uint off;
  uint ops = 1;
};

/* be32 dst */
struct be32 {
  uint off;
  uint ops = 1;
};

/* be64 dst */
struct be64 {
  uint off;
  uint ops = 1;
};

/* addx16 dst src off */
struct addx16 {
  uint off;
  uint ops = 3;
};

/* addx32 dst src off */
struct addx32 {
  uint off;
  uint ops = 3;
};

/* addx64 dst src off */
struct addx64 {
  uint off;
  uint ops = 3;
};

/* andx16 dst src off */
struct andx16 {
  uint off;
  uint ops = 3;
};

/* andx32 dst src off */
struct andx32 {
  uint off;
  uint ops = 3;
};

/* andx64 dst src off */
struct andx64 {
  uint off;
  uint ops = 3;
};

/* orx16 dst src off */
struct orx16 {
  uint off;
  uint ops = 3;
};

/* orx32 dst src off */
struct orx32 {
  uint off;
  uint ops = 3;
};

/* orx64 dst src off */
struct orx64 {
  uint off;
  uint ops = 3;
};

/* xorx16 dst src off */
struct xorx16 {
  uint off;
  uint ops = 3;
};

/* xorx32 dst src off */
struct xorx32 {
  uint off;
  uint ops = 3;
};

/* xorx64 dst src off */
struct xorx64 {
  uint off;
  uint ops = 3;
};

/* addfx16 dst src off */
struct addfx16 {
  uint off;
  uint ops = 3;
};

/* addfx32 dst src off */
struct addfx32 {
  uint off;
  uint ops = 3;
};

/* addfx64 dst src off */
struct addfx64 {
  uint off;
  uint ops = 3;
};

/* andfx16 dst src off */
struct andfx16 {
  uint off;
  uint ops = 3;
};

/* andfx32 dst src off */
struct andfx32 {
  uint off;
  uint ops = 3;
};

/* andfx64 dst src off */
struct andfx64 {
  uint off;
  uint ops = 3;
};

/* orfx16 dst src off */
struct orfx16 {
  uint off;
  uint ops = 3;
};

/* orfx32 dst src off */
struct orfx32 {
  uint off;
  uint ops = 3;
};

/* orfx64 dst src off */
struct orfx64 {
  uint off;
  uint ops = 3;
};

/* xorfx16 dst src off */
struct xorfx16 {
  uint off;
  uint ops = 3;
};

/* xorfx32 dst src off */
struct xorfx32 {
  uint off;
  uint ops = 3;
};

/* xorfx64 dst src off */
struct xorfx64 {
  uint off;
  uint ops = 3;
};

/* xchgx16 dst src off */
struct xchgx16 {
  uint off;
  uint ops = 3;
};

/* xchgx32 dst src off */
struct xchgx32 {
  uint off;
  uint ops = 3;
};

/* xchgx64 dst src off */
struct xchgx64 {
  uint off;
  uint ops = 3;
};

/* cmpxchgx16 dst src off */
struct cmpxchgx16 {
  uint off;
  uint ops = 3;
};

/* cmpxchgx32 dst src off */
struct cmpxchgx32 {
  uint off;
  uint ops = 3;
};

/* cmpxchgx64 dst src off */
struct cmpxchgx64 {
  uint off;
  uint ops = 3;
};

/* ldmapfd dst imm */
struct ldmapfd {
  uint off;
  uint ops = 2;
};

/* ld64 dst imm */
struct ld64 {
  uint off;
  uint ops = 2;
};

/* ldabs8 imm */
struct ldabs8 {
  uint off;
  uint ops = 2;
};

/* ldabs16 imm */
struct ldabs16 {
  uint off;
  uint ops = 2;
};

/* ldabs32 imm */
struct ldabs32 {
  uint off;
  uint ops = 2;
};

/* ldabs64 imm */
struct ldabs64 {
  uint off;
  uint ops = 2;
};

/* ldind8 src imm */
struct ldind8 {
  uint off;
  uint ops = 2;
};

/* ldind16 src imm */
struct ldind16 {
  uint off;
  uint ops = 2;
};

/* ldind32 src imm */
struct ldind32 {
  uint off;
  uint ops = 2;
};

/* ldind64 src imm */
struct ldind64 {
  uint off;
  uint ops = 2;
};

/* ldx8 dst src off */
struct ldx8 {
  uint off;
  uint ops = 3;
};

/* ldx16 dst src off */
struct ldx16 {
  uint off;
  uint ops = 3;
};

/* ldx32 dst src off */
struct ldx32 {
  uint off;
  uint ops = 3;
};

/* ldx64 dst src off */
struct ldx64 {
  uint off;
  uint ops = 3;
};

/* st8 dst off imm */
struct st8 {
  uint off;
  uint ops = 3;
};

/* st16 dst off imm */
struct st16 {
  uint off;
  uint ops = 3;
};

/* ST32 dst off imm */
struct st32 {
  uint off;
  uint ops = 3;
};

/* ST64 dst off imm */
struct st64 {
  uint off;
  uint ops = 3;
};

/* stx8 dst off imm */
struct stx8 {
  uint off;
  uint ops = 3;
};

/* stx16 dst off imm */
struct stx16 {
  uint off;
  uint ops = 3;
};

/* stx32 dst off imm */
struct stx32 {
  uint off;
  uint ops = 3;
};

/* stx64 dst off imm */
struct stx64 {
  uint off;
  uint ops = 3;
};

/* stxx8 dst off imm */
struct stxx8 {
  uint off;
  uint ops = 3;
};

/* stxx16 dst off imm */
struct stxx16 {
  uint off;
  uint ops = 3;
};

/* stxx32 dst off imm */
struct stxx32 {
  uint off;
  uint ops = 3;
};

/* stxx64 dst off imm */
struct stxx64 {
  uint off;
  uint ops = 3;
};

/* ja off */
struct ja {
  int32_t off;
  uint ops = 1;
};

/* jeq dst imm off */
/* jeq  dst src off */
struct jeq {
  int32_t off;
  uint ops = 3;
};

/* jgt dst imm off */
/* jgt  dst src off */
struct jgt {
  int32_t off;
  uint ops = 3;
};

/* jge dst imm off */
/* jge  dst src off */
struct jge {
  int32_t off;
  uint ops = 3;
};

/* jlt dst imm off */
/* jlt  dst src off */
struct jlt {
  int32_t off;
  uint ops = 3;
};

/* jle dst imm off */
/* jle  dst src off */
struct jle {
  int32_t off;
  uint ops = 3;
};

/* jset dst imm off */
/* jset  dst src off */
struct jset {
  int32_t off;
  uint ops = 3;
};

/* jne dst imm off */
/* jne  dst src off */
struct jne {
  int32_t off;
  uint ops = 3;
};

/* jsgt dst imm off */
/* jsgt  dst src off */
struct jsgt {
  int32_t off;
  uint ops = 3;
};

/* jsge dst imm off */
/* jsge  dst src off */
struct jsge {
  int32_t off;
  uint ops = 3;
};

/* jslt dst imm off */
/* jslt  dst src off */
struct jslt {
  int32_t off;
  uint ops = 3;
};

/* jsle dst imm off */
/* jsle  dst src off */
struct jsle {
  int32_t off;
  uint ops = 3;
};

/* call imm */
struct call {
  int32_t off;
  uint ops = 1;
};

/* rel imm */
struct rel {
  int32_t off;
  uint ops = 1;
};

/* exit */
struct exit_ins {
  int32_t off;
  uint ops = 0;
};

/* jeq32 dst imm off */
/* jeq32  dst src off */
struct jeq32 {
  int32_t off;
  uint ops = 3;
};

/* jgt32 dst imm off */
/* jgt32  dst src off */
struct jgt32 {
  int32_t off;
  uint ops = 3;
};

/* jge32 dst imm off */
/* jge32  dst src off */
struct jge32 {
  int32_t off;
  uint ops = 3;
};

/* jlt32 dst imm off */
/* jlt32  dst src off */
struct jlt32 {
  int32_t off;
  uint ops = 3;
};

/* jle32 dst imm off */
/* jle32  dst src off */
struct jle32 {
  int32_t off;
  uint ops = 3;
};

/* jset32 dst imm off */
/* jset32  dst src off */
struct jset32 {
  int32_t off;
  uint ops = 3;
};

/* jne32 dst imm off */
/* jne32  dst src off */
struct jne32 {
  int32_t off;
  uint ops = 3;
};

/* jsgt32 dst imm off */
/* jsgt32  dst src off */
struct jsgt32 {
  int32_t off;
  uint ops = 3;
};

/* jsge32 dst imm off */
/* jsge32  dst src off */
struct jsge32 {
  int32_t off;
  uint ops = 3;
};

/* jslt32 dst imm off */
/* jslt32  dst src off */
struct jslt32 {
  int32_t off;
  uint ops = 3;
};

/* jsle32 dst imm off */
/* jsle32  dst src off */
struct jsle32 {
  int32_t off;
  uint ops = 3;
};

/* zext dst */
struct zext {
  int32_t off;
  uint ops = 1;
};

#endif
