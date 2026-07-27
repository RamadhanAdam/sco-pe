```markdown
# sco-pe

PE (Portable Executable) file parser in C. Lightweight, no external dependencies, built for static analysis.

## Build

```bash
make
```

Binary is `bin/scope`.

## Run

```bash
./bin/scope <file>
```

Output includes:

- file size, architecture (x86/x64/ARM)
- DOS header (`e_lfanew`)
- NT headers (magic, section count)
- section table: virtual address, virtual size, raw size, R/W/X permissions
- imports: DLL names + all imported functions (named imports only)
- exports: function names, DLL name if present
- overlay detection: shows if extra data exists past the last section or authenticode signature

Example:

```text
[Imports] (8 DLLs)
  KERNEL32.dll (12 functions)
    └── CreateFileA
    └── WriteFile
    └── ...
```

## Test

```bash
make test
```

Runs the unit test suite covering all parsers: file, DOS, NT, sections, utils (RVA to offset), imports, exports, and the security/bounds module.

## Security / bounds checking

All parsers share `security.c`:

- `pe_bounds_ok()` – validate that a read range fits in the file
- `pe_count_plausible()` – reject insane table counts
- `pe_safe_strcpy()` – copy a string from the PE buffer without reading past EOF, even if no null terminator exists

This makes the tool safe for untrusted input.

## Extras

`tools/c/overlay_extract.c` and `tools/py/overlay_extract.py` extract appended overlay data (ignores authenticode signature). Useful for finding hidden payloads.

Build the C version:

```bash
gcc tools/c/overlay_extract.c -o overlay
```

Run:

```bash
overlay_extract input.exe output.bin
```

Python version requires `pefile`.

---

Parsing pipeline is complete and production-ready.
```