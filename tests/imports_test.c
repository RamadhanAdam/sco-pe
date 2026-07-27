// tests/imports_test.c - tests for parse_imports
// build: gcc -Iinclude src/dos.c src/nt.c src/sections.c src/utils.c src/imports.c tests/imports_test.c -o bin/imports_test
// run:   ./bin/imports_test
#include "pe.h"
#include "dos.h"
#include "nt.h"
#include "sections.h"
#include "imports.h"
#include <stdio.h>
#include <string.h>

// Mocking layout coordinates:
// - NT headers mapped at 0x80
// - 1 Section Header mapped on disk at 0x400 (corresponds to RVA 0x1000)
// - Import descriptors injected exactly at file offset 0x400
// - Target name character arrays placed slightly higher at offset 0x450 (RVA 0x1050)
static long build_valid_pe(unsigned char *buf) {
    memset(buf, 0, 2048);

    // Initialize required baseline DOS pointers
    DOS_HEADER *dos = (DOS_HEADER *)buf;
    dos->e_magic = 0x5A4D;
    dos->e_lfanew = 0x80;

    // Initialize required baseline PE machine structural flags
    NT_HEADERS *nt = (NT_HEADERS *)(buf + dos->e_lfanew);
    nt->signature = 0x00004550;
    nt->file_header.number_of_sections = 1;
    nt->file_header.size_of_optional_header = sizeof(OPTIONAL_HEADER);
    nt->optional_header.magic = 0x20b;
    nt->optional_header.data_directory[DIR_IMPORT].virtual_address = 0x1000;
    nt->optional_header.data_directory[DIR_IMPORT].size = 64;

    // Map section alignment structures to clear rva_to_offset parsing hurdles
    unsigned char *table = (unsigned char *)nt + 4 + sizeof(FILE_HEADER)
        + nt->file_header.size_of_optional_header;

    SECTION_HEADER *s1 = (SECTION_HEADER *)table;
    memcpy(s1->name, ".idata", 7);
    s1->virtual_address = 0x1000;
    s1->virtual_size = 0x200;
    s1->pointer_to_raw_data = 0x400;

    // Forge an active import table entry inside the file data chunk
    IMPORT_DESCRIPTOR *desc = (IMPORT_DESCRIPTOR *)(buf + 0x400);
    desc->name = 0x1050; // Points to RVA holding string literal data
    desc->first_thunk = 0x1100;

    // Inject a null terminal entry following the first record to break the loop safely
    IMPORT_DESCRIPTOR *end = desc + 1;
    memset(end, 0, sizeof(IMPORT_DESCRIPTOR));

    // Store string character array explicitly inside the mock file buffer
    strcpy((char *)(buf + 0x450), "KERNEL32.dll");

    return 0x600; 
}

// Helper wrapper to initialize a target PEFile context
static PEFile make_pe(unsigned char *buf, long size) {
    PEFile pe = {0};
    pe.buffer = buf;
    pe.size = size;
    return pe;
}

// Asserts a test condition and prints formatted PASS/FAIL status
static int expect(int cond, const char *label) {
    printf("[%s] %s\n", cond ? "PASS" : "FAIL", label);
    return cond;
}

int main(void) {
    unsigned char buf[2048];
    int failures = 0;

    // --- Happy Path Testing ---
    long size = build_valid_pe(buf);
    PEFile pe = make_pe(buf, size);
    parse_dos_header(&pe);
    parse_nt_headers(&pe);
    parse_sections(&pe);

    ImportTable imports;
    failures += !expect(parse_imports(&pe, &imports) == 0, "valid imports parse successfully");
    failures += !expect(imports.count == 1, "one DLL found");
    failures += !expect(strcmp(imports.dlls[0].name, "KERNEL32.dll") == 0, "DLL name read correctly");

    // --- Edge Case Testing: Blank Directories ---
    build_valid_pe(buf);
    pe = make_pe(buf, size);
    parse_dos_header(&pe);
    parse_nt_headers(&pe);
    parse_sections(&pe);
    
    // Explicitly wipe the import reference offsets down to zero
    pe.nt_headers->optional_header.data_directory[DIR_IMPORT].virtual_address = 0;
    pe.nt_headers->optional_header.data_directory[DIR_IMPORT].size = 0;

    ImportTable none;
    failures += !expect(parse_imports(&pe, &none) == 0, "missing import directory is not an error");
    failures += !expect(none.count == 0, "zero DLLs found when no import directory");

    printf("\n%s\n", failures == 0 ? "All tests passed" : "Some tests FAILED");
    return failures == 0 ? 0 : 1;
}
