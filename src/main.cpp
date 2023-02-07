#include "ast.hpp"
#include "parser.hpp"
#include "typechecker.hpp"
#include "optimizer.hpp"
#include "codegen.hpp"
#include "utils.hpp"

int main(int argc, char **argv) {
  std::vector<std::string> filenames;
  std::vector<std::string> out_filenames;
  std::vector<std::string> struct_names;

  parse_opts(argc, argv, filenames, out_filenames, struct_names);

  std::string filename, out_filename = "", struct_name = "";
  uint files = filenames.size();

  for(uint i=0; i<files; i++) {
    filename = filenames[i];
    if (struct_names.size())
      struct_name = struct_names[i];

    if (out_filenames.size())
      out_filename = out_filenames[i];
    else
      out_filename = filename.substr(0, filename.size()-2);

    if (access(filename.c_str(), F_OK) != 0)
      error("error: file `", filename, "` cannot be accessed: ",
            strerror(errno));

    std::ifstream ifs(filename);
    std::stringstream ss;
    ss << ifs.rdbuf();
    bytecode = ss.str();

    ss.str(std::string());
    ss.clear();
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
    dealloc_ast();
  }

  return 0;
}
