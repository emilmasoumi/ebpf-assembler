CC = gcc
CXX = g++
CFLAGS = -std=c99 -O2 -Wall -Wextra -pedantic-errors -Wshadow \
-Wstrict-aliasing -Werror -Wunreachable-code -Wno-long-long
CXXFLAGS = -std=c++17 -fconcepts -Wshadow -Wstrict-aliasing -Werror \
-Wunreachable-code -Wno-long-long -pedantic-errors -Wall -Wextra -O2 \
-isystem headers/
LDLIBS = -lm
LDFLAGS = -g
CNOPEDANTICFLAGS = -std=c99 -O2 -Wall -Wextra -Wshadow -Wstrict-aliasing \
-Werror -Wunreachable-code -Wno-long-long

SRC = src
TESTS = tests
HEADERS = headers

SRCS := $(shell find $(SRC) -name "*.cpp")
OBJS := $(patsubst %.cpp, %.o, $(SRCS))

all: ebpf-as objdump-ebpf load_ebpf load_ebpf_macros

ebpf-as: $(SRC)/*.cpp $(SRC)/*.h $(HEADERS)/*.h $(OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $(LDLIBS) -o $@ $(OBJS)

objdump-ebpf: $(SRC)/objdump.c $(HEADERS)/*.h
	$(CC) $(CFLAGS) $(LDLIBS) $(SRC)/objdump.c -o $@

load_ebpf: $(TESTS)/load_ebpf.c $(HEADERS)/*.h
	$(CC) $(CFLAGS) $(TESTS)/load_ebpf.c -o $@

load_ebpf_macros: $(TESTS)/load_ebpf_macros.c $(TESTS)/macros.h $(HEADERS)/*.h
	$(CC) $(CNOPEDANTICFLAGS) $(TESTS)/load_ebpf_macros.c -o $@

clean:
	rm -f ebpf-as load_ebpf load_ebpf_macros objdump-ebpf
	rm -f $(SRC)/*.o
