// src/utils.c
// Shared helpers: RVA -> file offset conversion
// RVA-to-file-offset conversion, used by sections, imports, and exports
#include "utils.h"

long rva_to_offset(PEFile *pe, unsigned int rva) {
    unsigned short count = pe->nt_headers->file_header.number_of_sections;

    // Scan through all available section headers to find which one bounds the RVA
    for (unsigned short i = 0; i < count; i++) {
        SECTION_HEADER *s = &pe->sections[i];
        
        // Handle uninitialized virtual size fields using fallback raw data constraints
        unsigned int size = s->virtual_size ? s->virtual_size : s->size_of_raw_data;

        // Verify if the target RVA falls within the current section's virtual boundaries
        if (rva >= s->virtual_address && rva < s->virtual_address + size) {
            // Calculate the internal section offset and project it onto the raw disk position
            return (long)(rva - s->virtual_address) + s->pointer_to_raw_data;
        }
    }
    // Return error if RVA does not fall within any mapped section
    return -1;
}
