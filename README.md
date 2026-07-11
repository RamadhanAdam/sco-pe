# sco-pe

A lightweight, extensible C library for parsing and analyzing Windows PE (Portable Executable) files.

## Building it

Run `make` to compile everything. The final binary shows up at `bin/scope`.

## Running the tests

Run `make test` to compile and run the test suite. Right now that covers `file.c` — opening a real PE file and confirming it reads the correct number of bytes.

## Currently

File I/O is working — opening a PE file, reading it into memory, and freeing it afterward. DOS header, NT headers, sections, imports, and exports are still being built out.
