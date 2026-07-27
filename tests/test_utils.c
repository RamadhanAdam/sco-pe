// tests/utils_test.c - tests for rva_to_offset
// build: gcc -Iinclude src/dos.c src/nt.c src/sections.c src/utils.c tests/utils_test.c -o bin/utils_test
// run:   ./bin/utils_test
#include "pe.h"
#include "dos.h"
#include "nt.h"
#include "sections.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>

// Constructs a valid, minimal in-memory PE file layout containing one mock section
static long build_valid_pe(unsigned char *buf) {
    memset(buf, 0, 1024);

    // Initialize minimal DOS Header
    DOS_HEADER *dos = (DOS_HEADER *)buf;
    dos->e_magic = 0x5A4D;
    dos->e_lfanew = 0x80;

    // Initialize NT Headers specifying 1 section
    NT_HEADERS *nt = (NT_HEADERS *)(buf + dos->e_lfanew);
    nt->signature = 0x00004550;
    nt->file_header.number_of_sections = 1;
    nt->file_header.size_of_optional_header = sizeof(OPTIONAL_HEADER);
    nt->optional_header.magic = 0x20b;

    // Skip all headers to locate the start of the section table array
    unsigned char *table = (unsigned char *)nt + 4 + sizeof(FILE_HEADER)
        + nt->file_header.size_of_optional_header;

    // Define boundaries for the .text section (Virtual: 0x1000-0x1200, Disk: Starts at 0x400)
    SECTION_HEADER *s1 = (SECTION_HEADER *)table;
    memcpy(s1->name, ".text", 6);
    s1->virtual_address = 0x1000;
    s1->virtual_size = 0x200;
    s1->pointer_to_raw_data = 0x400;

    // Return the calculated total size of the mock PE data block
    return (table + sizeof(SECTION_HEADER) - buf) + 16;
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
    unsigned char buf[1024];
    int failures = 0;

    // Initialize context state across standard parser pipeline steps
    long size = build_valid_pe(buf);
    PEFile pe = make_pe(buf, size);
    parse_dos_header(&pe);
    parse_nt_headers(&pe);
    parse_sections(&pe);

    // Test 1: Verify correct translation mapping inside section memory space
    // RVA 0x1050 is 0x50 bytes into .text. Expected disk file offset: 0x400 + 0x50 = 0x450
    long off = rva_to_offset(&pe, 0x1050);
    failures += !expect(off == 0x450, "RVA inside section maps to correct file offset");

    // Test 2: Verify boundary checking against unmapped virtual space
    long bad = rva_to_offset(&pe, 0x9000);
    failures += !expect(bad == -1, "RVA outside all sections returns -1");

    printf("\n%s\n", failures == 0 ? "All tests passed" : "Some tests FAILED");
    return failures == 0 ? 0 : 1;
}
