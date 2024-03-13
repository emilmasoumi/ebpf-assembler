#ifndef UTILS
#define UTILS

#include <fstream>
#include <sstream>
#include <iostream>
#include <vector>

#define CRED "\x1B[1;31m"
#define CNRM "\x1B[0m"

#define ERR_STR CRED "error" CNRM ": "

#define MATCH switch
#define CASE  case
#define END   break;
#define _     default:

#define U(...) union {__VA_ARGS__}

#define TUPLE(sname, ...) \
  struct sname {          \
    __VA_ARGS__           \
  }

#define IO  std::cout
#define STR std::to_string

typedef std::stringstream  SStream;
typedef std::istringstream ISStream;
typedef std::ifstream      IFStream;
typedef std::ofstream      OFStream;

template <typename T>
using Vector = std::vector<T>;

typedef float       Float;
typedef int         Int;
typedef int32_t     Int32;
typedef int64_t     Int64;
typedef const char* Id;
typedef std::string Str;
typedef size_t      Nat;

#define ARRAY_SIZE(arr) (sizeof(arr)/sizeof(arr[0]))

extern Nat optimize;
extern Nat cmacro;

void error();
template <typename T0, typename... Tn>
void error(T0 v0, Tn... vn) {
  IO << v0;
  error(vn...);
}

Int   stoi_w( const Str& str, Nat* idx = 0, Int base = 10);
Int64 stoll_w(const Str& str, Nat* idx = 0, Int base = 10);
Float stof_w( const Str& str, Nat* idx = 0);

Str highlight(Str, Nat, Nat);

void parse_opts(int, char**, Vector<Str>&, Vector<Str>&, Vector<Str>&);

#endif
