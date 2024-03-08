#ifndef CODEGEN
#define CODEGEN

#include "ast.hpp"
#include "utils.hpp"

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

void codegen(Str);
void codegen_str(Str, Str);

#endif
