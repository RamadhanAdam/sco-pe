// Tests for parse_nt_headers: valid PE32+, bad signature, bad magic, truncated buffer
#include "pe.h"
#include "dos.h"
#include "nt.h"
#include <stdio.h>
#include <string.h>

// Builds a minimal valid buffer: DOS header + NT headers (PE32+) at e_lfanew.
// Returns the buffer size. Caller supplies a big-enough buffer.
static long build_valid_pe(unsigned char *buf) {
    memset(buf, 0, 512);

    DOS_HEADER *dos = (DOS_HEADER *)buf;
    dos->e_magic = 0x5A4D;   // "MZ"
    dos->e_lfanew = 0x80;    // arbitrary valid offset, room for DOS header

    NT_HEADERS *nt = (NT_HEADERS *)(buf + dos->e_lfanew);
    nt->signature = 0x00004550;             // "PE\0\0"
    nt->file_header.number_of_sections = 3;
    nt->file_header.size_of_optional_header = sizeof(OPTIONAL_HEADER);
    nt->optional_header.magic = 0x20b;      // PE32+
    nt->optional_header.size_of_headers = 0x400;

    return dos->e_lfanew + sizeof(NT_HEADERS) + 16; // a little slack
}

static PEFile make_pe(unsigned char *buf, long size) {
    PEFile pe = {0};
    pe.buffer = buf;
    pe.size = size;
    return pe;
}

static int expect(int cond, const char *label) {
    printf("[%s] %s\n", cond ? "PASS" : "FAIL", label);
    return cond;
}

int main(void) {
    unsigned char buf[512];
    int failures = 0;

    // --- Case 1: valid 64-bit PE ---
    long size = build_valid_pe(buf);
    PEFile pe = make_pe(buf, size);
    failures += !expect(parse_dos_header(&pe) == 0, "dos header parses");
    failures += !expect(parse_nt_headers(&pe) == 0, "valid NT headers parse successfully");
    failures += !expect(pe.nt_headers != NULL, "nt_headers pointer is set");
    failures += !expect(pe.nt_headers->file_header.number_of_sections == 3,
                         "number_of_sections read correctly");

    // --- Case 2: bad PE signature ---
    build_valid_pe(buf);
    pe = make_pe(buf, size);
    parse_dos_header(&pe);
    NT_HEADERS *nt = (NT_HEADERS *)(buf + pe.dos_header->e_lfanew);
    nt->signature = 0xDEADBEEF;
    failures += !expect(parse_nt_headers(&pe) == 1, "bad PE signature is rejected");

    // --- Case 3: bad optional header magic (e.g. PE32 instead of PE32+) ---
    build_valid_pe(buf);
    pe = make_pe(buf, size);
    parse_dos_header(&pe);
    nt = (NT_HEADERS *)(buf + pe.dos_header->e_lfanew);
    nt->optional_header.magic = 0x10b; // PE32, unsupported
    failures += !expect(parse_nt_headers(&pe) == 1, "non-PE32+ magic is rejected");

    // --- Case 4: truncated buffer (e_lfanew + NT_HEADERS overruns pe->size) ---
    build_valid_pe(buf);
    pe = make_pe(buf, size);
    parse_dos_header(&pe);
    pe.size = pe.dos_header->e_lfanew + 4; // way too small to hold NT_HEADERS
    failures += !expect(parse_nt_headers(&pe) == 1, "truncated buffer is rejected");

    printf("\n%s\n", failures == 0 ? "All tests passed" : "Some tests FAILED");
    return failures == 0 ? 0 : 1;
}