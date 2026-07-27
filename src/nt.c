// Parses NT headers: PE signature, File Header, Optional Header
#include "nt.h"
#include "pe.h"
#include <stdio.h>

int parse_nt_headers(PEFile *pe) {
    // e_lfanew was already bounds-checked in dos.c
    NT_HEADERS *nt = (NT_HEADERS *)(pe->buffer + pe->dos_header->e_lfanew);

    // bounds check: whole NT_HEADERS struct must fit in the buffer
    if (pe->dos_header->e_lfanew + (long)sizeof(NT_HEADERS) > pe->size) {
        printf("Error: NT headers go out of bounds\n");
        return 1;
    }

    // check "PE\0\0" signature
    if (nt->signature != 0x00004550) {
        printf("Error: not a valid PE file (bad PE signature)\n");
        return 1;
    }

    // only 64-bit PE (PE32+) supported
    if (nt->optional_header.magic != 0x20b) {
        printf("Error: only 64-bit PE files are supported\n");
        return 1;
    }

    pe->nt_headers = nt;
    return 0;
}