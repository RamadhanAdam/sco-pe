// Walks the import table: lists DLLs the file imports
#include "imports.h"
#include "utils.h"
#include "security.h"
#include <stdio.h>
#include <string.h>
#include "security.h"

int parse_imports(PEFile *pe, ImportTable *out) {
    out->count = 0;

    // Fetch the Virtual Address and Size markers for the Import Data Directory entry
    DATA_DIRECTORY dir = pe->nt_headers->optional_header.data_directory[DIR_IMPORT];
    if (dir.virtual_address == 0 || dir.size == 0) {
        return 0; // Standard case: clean return since missing imports do not violate format rules
    }

    // Convert the directory's Relative Virtual Address (RVA) to a concrete disk offset
    long offset = rva_to_offset(pe, dir.virtual_address);
    if (offset < 0 || offset >= pe->size) {
        printf("Error: import directory RVA out of bounds\n");
        return 1;
    }

    // Loop through the descriptor elements while enforcing buffer length constraints
    while (offset + (long)sizeof(IMPORT_DESCRIPTOR) <= pe->size) {
        IMPORT_DESCRIPTOR *desc = (IMPORT_DESCRIPTOR *)(pe->buffer + offset);

        // Windows PE Specification check: An entirely zeroed descriptor flags the end of the array
        if (desc->name == 0 && desc->first_thunk == 0 && desc->original_first_thunk == 0) {
            break; 
        }

        // Tracking down the raw file location of the actual ASCII character string for the DLL name
        long name_offset = rva_to_offset(pe, desc->name);
        if (!pe_bounds_ok(pe, name_offset, 1)) {
            printf("Error: import DLL name RVA out of bounds\n");
            return 1;
        }

        // Securely copying the string data if space remains in the output container
        if (out->count < MAX_IMPORTED_DLLS) {
            pe_safe_strcpy(pe, name_offset, out->dlls[out->count].name, sizeof(out->dlls[out->count].name));
            out->count++;
        }

        // Advance the offset to process the next sequential descriptor block
        offset += sizeof(IMPORT_DESCRIPTOR);
    }

    return 0;
}
