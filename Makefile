# Compiler and flags
CC := gcc
CFLAGS := -Wall -Wextra -Iinclude

# Automatically find every .c file in src/
SRC := $(wildcard src/*.c)

# Exclude src/main.c from core source objects used in tests
SRC_NO_MAIN := $(filter-out src/main.c, $(SRC))

# Convert the list of .c files into matching .o paths inside build/
OBJ := $(patsubst src/%.c, build/%.o, $(SRC))

# Automatically find every test file in tests/
TEST_SRCS := $(wildcard tests/*_test.c)

# Final executable target
# Linking all the .o files (in OBJ) into one binary at bin/scope
bin/scope: $(OBJ)
	$(CC) $^ -o $@

# Pattern rule: compile any src/X.c into build/X.o, creating output directories if needed
build/%.o: src/%.c
	@mkdir -p build bin
	$(CC) $(CFLAGS) -c $< -o $@

# Removing everything Make has built, so we can rebuild from scratch
.PHONY: clean
clean:
	rm -rf build/*.o bin/*

# Automatically builds and executes all test targets in the tests directory
.PHONY: test
test:
	@mkdir -p bin
	@for test_file in $(TEST_SRCS); do \
		echo "Building and running $$test_file..."; \
		bin_name=bin/$$(basename $$test_file .c); \
		$(CC) $(CFLAGS) $$test_file $(SRC_NO_MAIN) -o $$bin_name || exit 1; \
		./$$bin_name || exit 1; \
		echo "----------------------------------------"; \
	done
