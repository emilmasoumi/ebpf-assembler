#include "parser.hpp"
#include "typechecker.hpp"
#include "optimizer.hpp"
#include "codegen.hpp"
#include "utils.hpp"

int main(int argc, char **argv) {
  Vector<Str> filenames;
  Vector<Str> out_filenames;
  Vector<Str> struct_names;

  parse_opts(argc, argv, filenames, out_filenames, struct_names);

  Str filename, out_filename, struct_name;
  Nat files = filenames.size();

  for(Nat i=0; i<files; ++i) {
    filename = filenames[i];
    if (struct_names.size())
      struct_name = struct_names[i];

    if (out_filenames.size())
      out_filename = out_filenames[i];
    else
      out_filename = filename.substr(0, filename.size()-2);

    if (access(filename.c_str(), F_OK) != 0)
      error(ERR_STR "file `", filename, "` cannot be accessed: ",
            strerror(errno));

    IFStream ifs(filename);
    SStream ss;
    ss << ifs.rdbuf();
    bytecode = ss.str();

    SStream().swap(ss);
    ifs.close();

    parser();
    typechecker();

    if (optimize)
      optimizer();

    if (cmacro || struct_names.size())
      codegen_str(out_filename, struct_name);
    else
      codegen(out_filename);

    bytecode.clear();
    dealloc();
  }

  return 0;
}
