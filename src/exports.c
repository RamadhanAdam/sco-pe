// Walks the export table: lists functions the file exposes (DLLs only)
#include "exports.h"
#include "utils.h"
#include "security.h"
#include <stdio.h>
#include <string.h>

int parse_exports(PEFile *pe, ExportTable *out){
    out->count = 0;
    out->dll_name[0] = '\0';

    // Extract the address and size properties from the export data directory entry
    DATA_DIRECTORY dir = pe->nt_headers->optional_header.data_directory[DIR_EXPORT];
    if (dir.virtual_address == 0 || dir.size == 0) {
        return 0; // empty list
    }

    // Convert the directory's Relative Virtual Address (RVA) to a safe file offset
    long offset = rva_to_offset(pe, dir.virtual_address);
    if (offset < 0 || offset >= pe->size) {
        printf("Error: export directory RVA out of bounds\n");
        return 1;
    }

    // Referencing the structural data map directly out of the memory buffer
    if (!pe_bounds_ok(pe, offset, sizeof(EXPORT_DIRECTORY))) {
        printf("Error: export directory doesn't fit in file\n");
        return 1;
    }
    EXPORT_DIRECTORY *exp = (EXPORT_DIRECTORY *)(pe->buffer + offset);

    // Locating and resolve the string tracking the physical DLL file name string
    long name_offset = rva_to_offset(pe, exp->name);
    pe_safe_strcpy(pe, name_offset, out->dll_name, sizeof(out->dll_name));

    // Stop execution early if the export headers define no named function endpoints
    if (exp->number_of_names == 0) {
        return 0;
    }

    // Locate the parallel array holding individual virtual function string pointers
    long names_offset = rva_to_offset(pe, exp->address_of_names);
    if (!pe_bounds_ok(pe, names_offset, (size_t)exp->number_of_names * sizeof(unsigned int))) {
        printf("Error: export name table RVA out of bounds\n");
        return 1;
    }

    // Cast the offset region to a standard 32-bit unsigned address pointer collection
    unsigned int *names_table = (unsigned int *)(pe->buffer + names_offset);

    // Iterate through the function list up to the constraints of our static container size
    unsigned int max_iter = exp->number_of_names;
    if (max_iter > MAX_EXPORTED_FUNCS) max_iter = MAX_EXPORTED_FUNCS;

    for (unsigned int i = 0; i < max_iter && out->count < MAX_EXPORTED_FUNCS; i++) {
        long func_name_offset = rva_to_offset(pe, names_table[i]);
        if (!pe_bounds_ok(pe, func_name_offset, 1)) continue;
        
        // Extract the raw ASCII text string detailing the exposed function symbol
        pe_safe_strcpy(pe, func_name_offset, out->funcs[out->count].name, sizeof(out->funcs[out->count].name));
        out->count++;
    }

    return 0;
}   