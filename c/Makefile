# Shield C Library Makefile

CC = gcc
CFLAGS = -Wall -Wextra -O2 -I./include
LDFLAGS =

# Source files
SRC = src/shield.c
TEST_SRC = tests/test_shield.c

# Output
LIB = libshield.a
TEST = test_shield

# Objects
OBJ = $(SRC:.c=.o)

.PHONY: all clean test lib

all: lib test

lib: $(LIB)

$(LIB): $(OBJ)
	ar rcs $@ $^

src/shield.o: src/shield.c include/shield.h
	$(CC) $(CFLAGS) -c $< -o $@

test: $(TEST)
	./$(TEST)

$(TEST): $(TEST_SRC) $(LIB)
	$(CC) $(CFLAGS) $(TEST_SRC) -L. -lshield $(LDFLAGS) -o $@

clean:
	rm -f $(OBJ) $(LIB) $(TEST)

# Install targets
PREFIX ?= /usr/local

install: lib
	install -d $(PREFIX)/lib
	install -d $(PREFIX)/include
	install -m 644 $(LIB) $(PREFIX)/lib/
	install -m 644 include/shield.h $(PREFIX)/include/

uninstall:
	rm -f $(PREFIX)/lib/$(LIB)
	rm -f $(PREFIX)/include/shield.h
