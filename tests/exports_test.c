// tests/exports_test.c - tests for parse_exports
// build: gcc -Iinclude src/dos.c src/nt.c src/sections.c src/utils.c src/exports.c tests/exports_test.c -o bin/exports_test
// run:   ./bin/exports_test
#include "pe.h"
#include "dos.h"
#include "nt.h"
#include "sections.h"
#include "exports.h"
#include <stdio.h>
#include <string.h>

// Mock layout blueprint constraints:
// - Baseline NT configuration maps directly onto offset 0x80
// - Target section headers open raw data mapping at offset 0x400 (matches virtual RVA 0x1000)
// - Export base descriptors open inside data buffer at offset 0x400
// - Custom function strings injected further up the space array (offsets 0x4A0/0x4B0)
static long build_valid_pe(unsigned char *buf) {
    memset(buf, 0, 2048);

    // Initialize minimal required structural components for the DOS wrapper region
    DOS_HEADER *dos = (DOS_HEADER *)buf;
    dos->e_magic = 0x5A4D;
    dos->e_lfanew = 0x80;

    // Set baseline target PE identity flags and point to export directory structures
    NT_HEADERS *nt = (NT_HEADERS *)(buf + dos->e_lfanew);
    nt->signature = 0x00004550;
    nt->file_header.number_of_sections = 1;
    nt->file_header.size_of_optional_header = sizeof(OPTIONAL_HEADER);
    nt->optional_header.magic = 0x20b;
    nt->optional_header.data_directory[DIR_EXPORT].virtual_address = 0x1000;
    nt->optional_header.data_directory[DIR_EXPORT].size = 64;

    // Skip preceding machine configurations to reach the section allocation table block
    unsigned char *table = (unsigned char *)nt + 4 + sizeof(FILE_HEADER)
        + nt->file_header.size_of_optional_header;

    // Define alignment parameters so that rva_to_offset logic operates predictably
    SECTION_HEADER *s1 = (SECTION_HEADER *)table;
    memcpy(s1->name, ".edata", 7);
    s1->virtual_address = 0x1000;
    s1->virtual_size = 0x300;
    s1->pointer_to_raw_data = 0x400;

    // Forge an active export directory block layout directly inside file buffer addresses
    EXPORT_DIRECTORY *exp = (EXPORT_DIRECTORY *)(buf + 0x400);
    exp->name = 0x1050;             // Points to the relative virtual address of the DLL name string
    exp->number_of_names = 2;       // Injects precisely two mock exported symbols
    exp->address_of_names = 0x1080; // Points to the relative array location holding string offsets

    // Write the raw identifying label for the module payload
    strcpy((char *)(buf + 0x450), "sample.dll");

    // Populate the names table with raw virtual target locations pointing to functional strings
    unsigned int *names_table = (unsigned int *)(buf + 0x480);
    names_table[0] = 0x10A0;
    names_table[1] = 0x10B0;

    // Inject literal string tokens into raw storage regions inside our array map
    strcpy((char *)(buf + 0x4A0), "FuncOne");
    strcpy((char *)(buf + 0x4B0), "FuncTwo");

    return 0x600;
}

// Inline setup wrapper to generate clean context structures across test blocks
static PEFile make_pe(unsigned char *buf, long size) {
    PEFile pe = {0};
    pe.buffer = buf;
    pe.size = size;
    return pe;
}

// Standard verification helper to log formatted PASS or FAIL message metrics
static int expect(int cond, const char *label) {
    printf("[%s] %s\n", cond ? "PASS" : "FAIL", label);
    return cond;
}

int main(void) {
    unsigned char buf[2048];
    int failures = 0;

    // --- Happy Path Testing Sequence ---
    long size = build_valid_pe(buf);
    PEFile pe = make_pe(buf, size);
    parse_dos_header(&pe);
    parse_nt_headers(&pe);
    parse_sections(&pe);

    ExportTable exports;
    failures += !expect(parse_exports(&pe, &exports) == 0, "valid exports parse successfully");
    failures += !expect(strcmp(exports.dll_name, "sample.dll") == 0, "DLL name read correctly");
    failures += !expect(exports.count == 2, "two functions found");
    failures += !expect(strcmp(exports.funcs[0].name, "FuncOne") == 0, "first function name correct");
    failures += !expect(strcmp(exports.funcs[1].name, "FuncTwo") == 0, "second function name correct");

    // --- Edge Case Testing Sequence: Empty Export References ---
    build_valid_pe(buf);
    pe = make_pe(buf, size);
    parse_dos_header(&pe);
    parse_nt_headers(&pe);
    parse_sections(&pe);
    
    // Completely clear directory entry addresses to verify empty table edge-cases
    pe.nt_headers->optional_header.data_directory[DIR_EXPORT].virtual_address = 0;
    pe.nt_headers->optional_header.data_directory[DIR_EXPORT].size = 0;

    ExportTable none;
    failures += !expect(parse_exports(&pe, &none) == 0, "missing export directory is not an error");
    failures += !expect(none.count == 0, "zero functions found when no export directory");

    printf("\n%s\n", failures == 0 ? "All tests passed" : "Some tests FAILED");
    return failures == 0 ? 0 : 1;
}
