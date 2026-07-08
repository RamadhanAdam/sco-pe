# Compiler and flags
CC := gcc
CFLAGS := -Wall -Wextra -Iinclude

# Automatically find every .c file in src/
SRC := $(wildcard src/*.c)

# Convert the list of .c files into matching .o paths inside build/
OBJ := $(patsubst src/%.c, build/%.o, $(SRC))

# Final executable target
# Linking all the .o files (in OBJ) into one binary at bin/scope
bin/scope: $(OBJ)
	$(CC) $^ -o $@

# Pattern rule: compile any src/X.c into build/X.o
build/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Removing everything Make has built, so we can rebuild from scratch
.PHONY: clean
clean:
	rm -rf build/*.o bin/scope