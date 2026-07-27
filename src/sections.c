// Parses the section table: name, virtual address, size, characteristics
#include "sections.h"
#include "pe.h"
#include <stdio.h>

int parse_sections(PEFile *pe) {
    unsigned short count = pe->nt_headers->file_header.number_of_sections;

    // Skip PE Signature (4 bytes), File Header, and Optional Header to reach Section Table
    unsigned char *table = (unsigned char *)pe->nt_headers
        + 4
        + sizeof(FILE_HEADER)
        + pe->nt_headers->file_header.size_of_optional_header;

    // Calculate file offsets to verify memory boundaries
    long table_start = table - pe->buffer;
    long table_end = table_start + (long)count * (long)sizeof(SECTION_HEADER);

    // Guard against malformed files that overflow the buffer
    if (table_start < 0 || table_end > pe->size) {
        printf("Error: section table goes out of bounds\n");
        return 1;
    }

    pe->sections = (SECTION_HEADER *)table;
    return 0;
}
