CC = gcc
CXX = g++
ASAN = -fsanitize=address -fsanitize=pointer-compare -fsanitize=leak \
-fsanitize=undefined
CFLAGS = -std=c99 -O2 -Wall -Wextra -pedantic-errors -Wshadow \
-Wstrict-aliasing -Werror -Wunreachable-code -Wno-long-long
CXXFLAGS = -std=c++20 -fconcepts -Wshadow -Wstrict-aliasing -Werror \
-Wunreachable-code -Wno-long-long -pedantic-errors -Wall -Wextra -O2 \
-Wno-missing-field-initializers -isystem headers/
LDLIBS = -lm
LDFLAGS = -g
CNOPEDANTICFLAGS = -std=c99 -O2 -Wall -Wextra -Wshadow -Wstrict-aliasing \
-Werror -Wunreachable-code -Wno-long-long

SRC = src
TESTS = tests
HEADERS = headers

SRCS := $(shell find $(SRC) -maxdepth 1 -name "*.cpp")
OBJS := $(patsubst %.cpp, %.o, $(SRCS))

all: ebpf-as disas-ebpf load_ebpf load_ebpf_macros

ebpf-as: $(SRC)/*.cpp $(SRC)/*.hpp $(HEADERS)/*.h $(OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $(LDLIBS) -o $@ $(OBJS)

disas-ebpf: $(SRC)/disas.c $(HEADERS)/*.h
	$(CC) $(CFLAGS) $(LDLIBS) $(SRC)/disas.c -o $@

load_ebpf: $(TESTS)/load_ebpf.c $(HEADERS)/*.h
	$(CC) $(CFLAGS) $(TESTS)/load_ebpf.c -o $@

load_ebpf_macros: $(TESTS)/load_ebpf_macros.c $(TESTS)/macros.h $(HEADERS)/*.h
	$(CC) $(CNOPEDANTICFLAGS) $(TESTS)/load_ebpf_macros.c -o $@

clean:
	rm -f ebpf-as load_ebpf load_ebpf_macros disas-ebpf $(SRC)/*.o
