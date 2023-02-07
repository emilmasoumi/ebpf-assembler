CC = gcc
CNOPEDANTICFLAGS = -std=c99 -O2 -Wall -Wextra -Wshadow -Wstrict-aliasing \
-Werror -Wunreachable-code -Wno-long-long

TESTS = tests
HEADERS = ../headers

all: tests

tests: tests.c tests.h $(HEADERS)/*.h
	$(CC) $(CNOPEDANTICFLAGS) tests.c -o $@

clean:
	rm -f tests
