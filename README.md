# sco-pe

A lightweight C library and command-line tool for parsing and analysing Windows Portable Executable (PE) files. The project manually parses PE structures without relying on external PE parsing libraries, making it suitable for learning the PE format, malware analysis, reverse engineering, and digital forensics.

## Features

* Parse DOS Header
* Parse NT Headers
* Parse File and Optional Headers
* Parse Section Table
* Display section permissions (Read, Write, Execute)
* Parse Import Directory
* Display imported DLLs and function names
* Parse Export Directory
* Display exported function names
* Detect PE overlay data
* Perform defensive bounds checking to safely handle malformed PE files

## Repository Structure

```text
.
├── include/    Header files
├── src/        Source code
├── tests/      Unit tests
├── samples/    Sample PE files
├── tools/      Standalone utilities
├── docs/       Build documentation
├── build/      Generated object files
├── bin/        Generated executables
├── Makefile
├── README.md
└── LICENSE
```

## Requirements

* GCC
* GNU Make
* A Unix-like environment (Linux or macOS)

## Building

Compile the project:

```bash
make
```

The executable will be generated at:

```text
bin/scope
```

Remove generated files:

```bash
make clean
```

## Usage

Analyse a PE file by providing its path as the first argument.

```bash
./bin/scope <pe_file>
```

The parser reports:

* File information
* DOS Header
* NT Headers
* Section Table
* Import Directory
* Export Directory
* Overlay information

## Testing

Run the complete test suite:

```bash
make test
```

The test suite validates:

* File loading
* DOS Header parsing
* NT Header parsing
* Section table parsing
* RVA-to-file offset conversion
* Import parsing
* Export parsing
* Shared security and bounds-checking routines

## Tools

The repository includes standalone utilities built using the same PE parsing concepts.

### C

`tools/c/overlay_extract.c`

Extracts overlay data appended after the PE image while accounting for the Authenticode Certificate Table.

Build:

```bash
gcc tools/c/overlay_extract.c -o overlay_extract
```

### Python

`tools/py/overlay_extract.py`

Python implementation of the same overlay extraction logic for scripting and rapid analysis.

## Documentation

Additional build documentation is available in the `docs/` directory.

## Contributing

Contributions are welcome. Bug reports, feature requests, and pull requests are appreciated.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
