# sco-pe

A lightweight, extensible C library for parsing and analyzing Windows PE (Portable Executable) files.

## Building it

Run `make` to compile everything. The final binary shows up at `bin/scope`.

## Running the tests

Run `make test` to compile and run the test suite. Currently covers `file.c` and `dos.c` — opening a real PE file, confirming it reads the correct number of bytes, and confirming the DOS header parses correctly.

## Currently

File I/O and DOS header parsing are working. NT headers, sections, imports, and exports are still being built out.

## Tools

Utilities built on top of the library concepts, not part of the core parsing API.

- `tools/c/overlay_extract.c` — extracts PE overlay data (anything appended after the last section) using raw Windows API struct parsing. Accounts for the Authenticode signature block so it isn't mistaken for overlay.
- `tools/py/overlay_extract.py` — same extraction logic using `pefile`, for quick scripting/analysis.

Overlays are commonly used to hide payloads, since most PE parsers stop reading at the end of the last section.

Build the C version with `gcc tools/c/overlay_extract.c -o overlay.exe`. Run either with:
```
overlay_extract <input.exe> <output.bin>
```