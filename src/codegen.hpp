#ifndef CODEGEN
#define CODEGEN

#include "ast.hpp"
#include "utils.hpp"

#include <cstring>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

void codegen(std::string);
void codegen_str(std::string, std::string);

#endif
