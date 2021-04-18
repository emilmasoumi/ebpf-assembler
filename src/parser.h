#ifndef PARSER
#define PARSER

#include "ast.h"
#include "symtab.h"
#include "utils.h"

static const std::string registers[] =
  {"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"};
static const std::string instructions[] =
  {"add", "sub", "mul", "div", "or", "and", "lsh", "rsh", "neg", "mod", "xor",
   "mov", "arsh",
   "add32", "sub32", "mul32", "div32", "or32", "and32", "lsh32", "rsh32",
   "neg32", "mod32", "xor32", "mov32", "arsh32",
   "le16", "le32", "le64", "be16", "be32", "be64",
   "addx16", "addx32", "addx64", "andx16", "andx32", "andx64", "orx16", "orx32",
   "orx64", "xorx16", "xorx32", "xorx64", "addfx16", "addfx32", "addfx64",
   "andfx16", "andfx32", "andfx64", "orfx16", "orfx32", "orfx64", "xorfx16",
   "xorfx32", "xorfx64", "xchgx16", "xchgx32", "xchgx64", "cmpxchgx16",
   "cmpxchgx32", "cmpxchgx64",
   "ldmapfd", "ld64", "ldabs8", "ldabs16", "ldabs32", "ldabs64", "ldind8",
   "ldind16", "ldind32", "ldind64", "ldx8", "ldx16", "ldx32", "ldx64", "st8",
   "st16", "st32", "st64", "stx8", "stx16", "stx32", "stx64", "stxx8", "stxx16",
   "stxx32", "stxx64",
   "ja", "jeq", "jgt", "jge", "jlt", "jle", "jset", "jne", "jsgt", "jsge",
   "jslt", "jsle", "call", "rel", "exit",
   "jeq32", "jgt32", "jge32", "jlt32", "jle32", "jset32", "jne32", "jsgt32",
   "jsge32", "jslt32", "jsle32",
   "zext"};

void parse_directive(std::string&, uint, uint);
void parse_lexeme(std::string&, uint, uint);
void parse_newline(std::string&, uint&, uint&, bool&);
void parser(void);

#endif
