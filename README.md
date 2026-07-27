# sco-pe

A lightweight, extensible C library for parsing and analyzing Windows PE (Portable Executable) files.

## Building it

Run `make` to compile everything. The final binary shows up at `bin/scope`.

## Running it

```bash
./bin/scope <path_to_pe_file>
```

Prints a full report: file size, DOS header, NT headers, sections, imports, and exports.

## Running the tests

Run `make test` to compile and run the full test suite:

- **file.c** — opens a real PE file, confirms correct byte count
- **dos.c** — parses DOS header, validates `e_lfanew`
- **nt.c** — parses NT headers, validates PE signature and PE32+ magic, rejects malformed buffers
- **sections.c** — parses section table, rejects implausible section counts and out-of-bounds tables
- **utils.c** — `rva_to_offset()`, converts RVAs to file offsets via section lookup
- **imports.c** — walks the import descriptor table, extracts imported DLL names
- **exports.c** — walks the export directory, extracts exported function names
- **security.c** — shared bounds-checking primitives used by every parser: validates struct reads stay within the file, caps implausible table counts, and safely copies strings without reading past EOF

## Currently

Core parsing pipeline is complete: DOS header → NT headers → sections → imports → exports, with full RVA-to-offset resolution and shared bounds validation via `security.c`. All modules have passing test coverage.

## Tools

Standalone utilities built on the same PE-parsing concepts, but not part of the core library API.

- `tools/c/overlay_extract.c` — extracts PE overlay data (anything appended after the last section) using raw Windows API struct parsing. Accounts for the Authenticode signature block so it isn't mistaken for overlay.
- `tools/py/overlay_extract.py` — same extraction logic using `pefile`, for quick scripting/analysis.

Overlays are commonly used to hide payloads, since most PE parsers stop reading at the end of the last section.

Build the C version:
```bash
gcc tools/c/overlay_extract.c -o overlay.exe
```

Run either version:
```bash
overlay_extract <input.exe> <output.bin>
```