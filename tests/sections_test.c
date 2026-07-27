// tests/sections_test.c - tests for parse_sections
// build: gcc -Iinclude src/dos.c src/nt.c src/sections.c tests/sections_test.c -o bin/sections_test
// run:   ./bin/sections_test
#include "pe.h"
#include "dos.h"
#include "nt.h"
#include "sections.h"
#include <stdio.h>
#include <string.h>

// Constructs a valid, minimal in-memory PE file layout for testing
static long build_valid_pe(unsigned char *buf) {
    memset(buf, 0, 1024);

    // Initialize minimal DOS Header
    DOS_HEADER *dos = (DOS_HEADER *)buf;
    dos->e_magic = 0x5A4D;
    dos->e_lfanew = 0x80;

    // Initialize NT Headers (PE signature, 2 sections, 64-bit optional header magic)
    NT_HEADERS *nt = (NT_HEADERS *)(buf + dos->e_lfanew);
    nt->signature = 0x00004550;
    nt->file_header.number_of_sections = 2;
    nt->file_header.size_of_optional_header = sizeof(OPTIONAL_HEADER);
    nt->optional_header.magic = 0x20b;

    // Locate section table position
    unsigned char *table = (unsigned char *)nt + 4 + sizeof(FILE_HEADER)
        + nt->file_header.size_of_optional_header;

    // Mock first section entry (.text)
    SECTION_HEADER *s1 = (SECTION_HEADER *)table;
    memcpy(s1->name, ".text", 6);
    s1->virtual_address = 0x1000;
    s1->virtual_size = 0x200;
    s1->size_of_raw_data = 0x200;
    s1->pointer_to_raw_data = 0x400;

    // Mock second section entry (.data)
    SECTION_HEADER *s2 = (SECTION_HEADER *)(table + sizeof(SECTION_HEADER));
    memcpy(s2->name, ".data", 6);
    s2->virtual_address = 0x2000;
    s2->virtual_size = 0x100;
    s2->size_of_raw_data = 0x100;
    s2->pointer_to_raw_data = 0x600;

    // Return the calculated total size of the mock PE data
    return (table + 2 * sizeof(SECTION_HEADER) - buf) + 16;
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

    //  Happy Path Tests 
    long size = build_valid_pe(buf);
    PEFile pe = make_pe(buf, size);
    parse_dos_header(&pe);
    parse_nt_headers(&pe);

    failures += !expect(parse_sections(&pe) == 0, "valid sections parse successfully");
    failures += !expect(pe.sections != NULL, "sections pointer is set");
    failures += !expect(strncmp(pe.sections[0].name, ".text", 5) == 0, "first section name is .text");
    failures += !expect(pe.sections[0].virtual_address == 0x1000, "first section virtual_address correct");
    failures += !expect(strncmp(pe.sections[1].name, ".data", 5) == 0, "second section name is .data");

    //  Boundary & Error Handling Tests 
    build_valid_pe(buf);
    pe = make_pe(buf, size);
    parse_dos_header(&pe);
    parse_nt_headers(&pe);
    
    // Artificially cut the file size short right before the section table starts
    pe.size = pe.dos_header->e_lfanew + sizeof(NT_HEADERS);

    failures += !expect(parse_sections(&pe) == 1, "truncated section table is rejected");

    printf("\n%s\n", failures == 0 ? "All tests passed" : "Some tests FAILED");
    return failures == 0 ? 0 : 1;
}
