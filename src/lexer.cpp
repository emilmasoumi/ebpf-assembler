/*
  Lexer tokenizing the string stream.
*/

#include "lexer.h"

void lexer() {

  std::string lexeme;
  bool comment = 0;
  uint line = 1, col = 1;

  for (char t : bytecode) {
    if (t == '\n')
      parse_newline(lexeme, line, col, comment);
    else if (t == ';')
      comment = 1;
    else if (comment)
      ;
    else if (isspace(t) && !lexeme.empty())
      parse_lexeme(lexeme, line, col);
    else if (isspace(t))
      ;
    else if (t == ':')
      parse_directive(lexeme, line, col);
    else
      lexeme += t;

    col++;
  }

}
