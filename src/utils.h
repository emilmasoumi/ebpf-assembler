#ifndef UTILS
#define UTILS

#include <fstream>
#include <sstream>

#define array_size(arr) (sizeof(arr)/sizeof(arr[0]))

extern std::string bytecode;

extern uint optimize;
extern uint cmacro;

void error();
template <typename T0, typename... Tn>
void error(T0 v0, Tn... vn) {
  std::cout<<v0;
  error(vn...);
}

int stoi_w(const std::string& str, std::size_t* idx = 0, int base = 10);
int stof_w(const std::string& str, std::size_t* idx = 0);

std::string err_getline(std::string, uint, uint);
std::string pp_spaces(std::string, uint);

void parse_opts(int, char**, std::vector<std::string>&,
                             std::vector<std::string>&,
                             std::vector<std::string>&);

#endif
