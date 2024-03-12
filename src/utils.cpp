#include "ast.hpp"
#include "utils.hpp"
#include <getopt.h>
#include <cstring>

Nat optimize = 0;
Nat cmacro   = 0;

void error() {
  IO << std::endl;
  exit(1);
}

// std::stoi() wrapper.
Int stoi_w(const Str& str, Nat* idx, Int base) {
  try {
    return std::stoi(str, idx, base);
  }

  catch (const std::invalid_argument& ia) {
    error(ERR_STR, ia.what(), ": invalid argument: for the value: ", str);
    return -1;
  }

  catch (const std::out_of_range& oor) {
    error(ERR_STR, oor.what(), ": out of range: for the value: ", str);
    return -2;
  }

  catch (const std::exception& e) {
    error(ERR_STR, e.what(), ": undefined error");
    return -3;
  }
}

// std::stoll() wrapper.
Int64 stoll_w(const Str& str, Nat* idx, Int base) {
  try {
    return std::stoll(str, idx, base);
  }

  catch (const std::invalid_argument& ia) {
    error(ERR_STR, ia.what(), ": invalid argument: for the value: ", str);
    return -1;
  }

  catch (const std::out_of_range& oor) {
    error(ERR_STR, oor.what(), ": out of range: for the value: ", str);
    return -2;
  }

  catch (const std::exception& e) {
    error(ERR_STR, e.what(), ": undefined error");
    return -3;
  }
}

// std::stof() wrapper.
Float stof_w(const Str& str, Nat* idx) {
  try {
    return std::stof(str, idx);
  }

  catch (const std::invalid_argument& ia) {
    error(ERR_STR, ia.what(), ": invalid argument: for the value: ", str);
    return -1.0;
  }

  catch (const std::out_of_range& oor) {
    error(ERR_STR, oor.what(), ": out of range: for the value: ", str);
    return -2.0;
  }

  catch (const std::exception& e) {
    error(ERR_STR, e.what(), ": undefined error");
    return -3.0;
  }
}

Str err_getline(Str id, Nat line_num, Nat col_num) {
  Str s, line;
  Str line_num_str = STR(line_num);
  Nat id_len       = 1;

  ISStream iss(bytecode);
  for (Nat i=0; i < line_num && std::getline(iss, line); ++i)
    ;;
  ISStream().swap(iss);

  if (id.size())
    id_len = id.size();

  (col_num < id_len + 1 ? col_num = 0 : col_num -= id_len + 1);

  s = "\n   " + line_num_str + " | " + line + "\n   "
    + Str(line_num_str.size(), ' ') + " | " + Str(col_num, ' ')
    + "^" + Str(id_len-1, '~');
  return s;
}

Str usage(char** argv) {
  Str usage;
  usage += "usage: ";
  usage += *argv;
  usage +=
    " <source> [options]\noptions:\n"
    "    {-O --opt}:\n"
    "\tEmploy various compiler optimization strageties to the bytecode.\n"
    "    {-c --cstruct} <arg>:\n"
    "\tCompile to preprocessing macros located in a C struct named <arg>.\n"
    "    {-m --macros}:\n"
    "\tCompile to preprocessing macros.\n"
    "    {-o --output} <arg>:\n"
    "\tOutput to the succeeding argument <arg>.\n"
    "    {-h --help}:\n"
    "\tDisplay this message.";
  return usage;
}

void parse_opts(int argc, char** argv,
                Vector<Str>& files,
                Vector<Str>& out_fnames,
                Vector<Str>& struct_names) {
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
    MATCH (opt) {
      case 'O':
        optimize = 1;
      END
      case 'c':
        struct_names.push_back(optarg);
      END
      case 'm':
        cmacro = 1;
      END
      case 'o':
        out_fnames.push_back(optarg);
      END
      case '?':
      case 'h':
      _
        error(usage(argv));
    }
  }

  if (optind == argc)
    error(usage(argv));

  auto ends_with = [](Str const& str, Str const& suffix) {
    if (suffix.size() > str.size())
      return false;
    return std::equal(suffix.rbegin(), suffix.rend(), str.rbegin());
  };

  for (int i=optind; i<argc; ++i) {
    if (strlen(argv[i]) < 3)
      error(ERR_STR "the file name is too short: ", argv[i]);
    else if (!ends_with(argv[i], ".s"))
      error(ERR_STR "unrecognized file extension for `", argv[i],
            "` expected a file extension of format `.s`");
    files.push_back(argv[i]);
  }

  if (cmacro && struct_names.size())
    error(ERR_STR "-c and -m cannot be set simultaneously");

  if (out_fnames.size() && out_fnames.size() != files.size())
    error(usage(argv), "\n\n" ERR_STR "the amount of -o <arg> provided must be"
          " equal to the amount of <sources> provided");
  else if (struct_names.size() && struct_names.size() != files.size())
    error(usage(argv), "\n\n" ERR_STR "the amount of -c <arg> provided must be"
          " equal to the amount of <sources> provided");
}
