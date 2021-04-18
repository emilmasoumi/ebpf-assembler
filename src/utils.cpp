#include "ast.h"
#include "utils.h"
#include <getopt.h>
#include <cstring>

std::string bytecode;

uint optimize = 0;
uint cmacro   = 0;

// Defined in `utils.h`
void error() {
  std::cout<<std::endl;
  exit(1);
}

std::string err_getline(std::string id, uint line_num, uint col_num) {
  if (col_num > id.size()+2)
    col_num -= id.size()+2;
  else
    col_num -= id.size();

  std::string line_num_str = std::to_string(line_num);
  std::string col_num_str  = std::to_string(col_num);
  uint line_num_size       = line_num_str.size();

  std::string s, line;
  std::istringstream iss(bytecode);

  for (uint i=0; i < line_num && std::getline(iss, line); i++)
    ;

  s = "\n   " + line_num_str + " | " + line + "\n   " +
      std::string(line_num_size, ' ') + " | " + std::string(col_num, ' ') +
      "^" + std::string(id.size(), '~');
  return s;
}

std::string pp_spaces(std::string s, uint lim) {
  if (s.length() < lim)
    return std::string(lim-s.length(), ' ');
  return std::string(" ");
}

std::string usage(char **argv) {
  std::string usage;
  usage += "usage: ";
  usage += *argv;
  usage +=
    " <source> [options]\noptions:\n"
    "    {-O --opt}:\n"
    "\tEmploys various compiler optimization strageties to the bytecode.\n"
    "    {-c --cstruct} <arg>:\n"
    "\tCompiles to preprocessing macros located in a C struct named <arg>.\n"
    "    {-m --macros}:\n"
    "\tCompiles to preprocessing macros.\n"
    "    {-o --output} <arg>:\n"
    "\tOutputs to the succeeding argument.\n"
    "    {-h --help}:\n"
    "\tDisplay this message.";
  return usage;
}

void parse_opts(int argc, char **argv,
                std::vector<std::string>& files,
                std::vector<std::string>& out_fnames,
                std::vector<std::string>& struct_names) {
  if (argc < 2)
    error(usage(argv));

  const option long_opts[] = {
    {"opt",     no_argument,       nullptr, 'O'},
    {"cstruct", required_argument, nullptr, 'c'},
    {"macros",  no_argument,       nullptr, 'm'},
    {"output",  required_argument, nullptr, 'o'},
    {"help",    no_argument,       nullptr, 'h'},
    {nullptr,   no_argument,       nullptr,   0}
  };

  while (1) {
    const int opt = getopt_long(argc, argv, "Oc:mo:h", long_opts, nullptr);
    if (opt == -1)
      break;
    switch (opt) {
      case 'O':
        optimize = 1;
        break;
      case 'c':
        struct_names.push_back(optarg);
        break;
      case 'm':
        cmacro = 1;
        break;
      case 'o':
        out_fnames.push_back(optarg);
        break;
      case '?':
        error("unrecognized option: ", optarg);
        break;
      case 'h':
      default:
        error(usage(argv));
        break;
    }
  }

  if (optind == argc)
    error(usage(argv));

  auto ends_with = [](std::string const& str, std::string const& suffix) {
    if (suffix.size() > str.size())
      return false;
    return std::equal(suffix.rbegin(), suffix.rend(), str.rbegin());
  };

  for (int i=optind; i<argc; i++) {
    if (!ends_with(argv[i], ".s"))
      error("error: unrecognized file extension for ``", argv[i],
            "`` expected a file extension of format ``.s``");
    if (strlen(argv[i]) < 3)
      error("error: file name too short: ", argv[i]);
    files.push_back(argv[i]);
  }

  if (cmacro && struct_names.size())
    error("error: -c and -m cannot be set simultaneously");

  if (out_fnames.size() && out_fnames.size() != files.size())
    error(usage(argv), "\n\nerror: the amount of -o <arg> provided must be"
          " equal to the amount of <sources> provided");
  else if (struct_names.size() && struct_names.size() != files.size())
    error(usage(argv), "\n\nerror: the amount of -c <arg> provided must be"
          " equal to the amount of <sources> provided");

}
