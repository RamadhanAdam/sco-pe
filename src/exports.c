// Walks the export table: lists functions the file exposes (DLLs only)
#include "exports.h"
#include "utils.h"
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
    EXPORT_DIRECTORY *exp = (EXPORT_DIRECTORY *)(pe->buffer + offset);

    // Locating and resolve the string tracking the physical DLL file name string
    long name_offset = rva_to_offset(pe, exp->name);
    if (name_offset >= 0 && name_offset < pe->size) {
        strncpy(out->dll_name, (char *)(pe->buffer + name_offset), 255);
        out->dll_name[255] = '\0'; // Guarantee a termination bound
    }

    // Stop execution early if the export headers define no named function endpoints
    if (exp->number_of_names == 0) {
        return 0;
    }

    // Locate the parallel array holding individual virtual function string pointers
    long names_offset = rva_to_offset(pe, exp->address_of_names);
    if (names_offset < 0 || names_offset >= pe->size) {
        printf("Error: export name table RVA out of bounds\n");
        return 1;
    }

    // Cast the offset region to a standard 32-bit unsigned address pointer collection
    unsigned int *names_table = (unsigned int *)(pe->buffer + names_offset);

    // Iterate through the function list up to the constraints of our static container size
    for (unsigned int i = 0; i < exp->number_of_names && out->count < MAX_EXPORTED_FUNCS; i++) {
        long func_name_offset = rva_to_offset(pe, names_table[i]);
        if (func_name_offset < 0 || func_name_offset >= pe->size) {
            continue; // Skip single broken pointers without derailing the rest of the parsing cycle
        }
        
        // Extract the raw ASCII text string detailing the exposed function symbol
        strncpy(out->funcs[out->count].name, (char *)(pe->buffer + func_name_offset), 255);
        out->funcs[out->count].name[255] = '\0'; // Clamp boundary buffer limits securely
        out->count++;
    }

    return 0;
}   