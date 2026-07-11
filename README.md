# sco-pe

A lightweight, extensible C library for parsing and analyzing Windows PE (Portable Executable) files.

## Building it

Run `make` to compile everything. The final binary shows up at `bin/scope`.

## Running the tests

Run `make test` to compile and run the test suite. Currently covers `file.c` and `dos.c` — opening a real PE file, confirming it reads the correct number of bytes, and confirming the DOS header parses correctly.

## Currently

File I/O and DOS header parsing are working. NT headers, sections, imports, and exports are still being built out.
