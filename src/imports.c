#include "imports.h"
#include "utils.h"
#include "security.h"
#include <stdio.h>
#include <string.h>

int parse_imports(PEFile *pe, ImportTable *out) {
    out->count = 0;

    DATA_DIRECTORY dir = pe->nt_headers->optional_header.data_directory[DIR_IMPORT];
    if (dir.virtual_address == 0 || dir.size == 0)
        return 0;

    long offset = rva_to_offset(pe, dir.virtual_address);
    if (offset < 0 || offset >= pe->size) {
        printf("Error: import directory RVA out of bounds\n");
        return 1;
    }

    while (offset + (long)sizeof(IMPORT_DESCRIPTOR) <= pe->size) {
        IMPORT_DESCRIPTOR *desc = (IMPORT_DESCRIPTOR *)(pe->buffer + offset);
        if (desc->name == 0 && desc->first_thunk == 0 && desc->original_first_thunk == 0)
            break;

        long name_offset = rva_to_offset(pe, desc->name);
        if (!pe_bounds_ok(pe, name_offset, 1)) {
            printf("Error: import DLL name RVA out of bounds\n");
            return 1;
        }

        if (out->count >= MAX_IMPORTED_DLLS) {
            offset += sizeof(IMPORT_DESCRIPTOR);
            continue;
        }

        // Copy DLL name
        pe_safe_strcpy(pe, name_offset, out->dlls[out->count].name,
                       sizeof(out->dlls[out->count].name));

        // ---- Use original_first_thunk (INT) for name walking ----
        unsigned int thunk_rva = desc->original_first_thunk;
        if (thunk_rva == 0) thunk_rva = desc->first_thunk;  // fallback

        out->dlls[out->count].func_count = 0;
        if (thunk_rva != 0) {
            long thunk_offset = rva_to_offset(pe, thunk_rva);
            if (thunk_offset >= 0 && thunk_offset < pe->size) {
                unsigned int *thunk = (unsigned int *)(pe->buffer + thunk_offset);
                int idx = 0;
                while (idx < MAX_IMPORTED_FUNCS) {
                    unsigned int val = thunk[idx];
                    if (val == 0) break;  // end of list

                    // If high bit set, it's an ordinal import – skip it
                    if ((val & 0x80000000) == 0) {
                        // RVA points to IMAGE_IMPORT_BY_NAME: skip 2‑byte hint
                        long func_name_offset = rva_to_offset(pe, val + 2);
                        if (pe_bounds_ok(pe, func_name_offset, 1)) {
                            pe_safe_strcpy(pe, func_name_offset,
                                           out->dlls[out->count].funcs[idx],
                                           sizeof(out->dlls[out->count].funcs[0]));
                            idx++;
                        }
                    } else {
                        // Ordinal – we could store the ordinal number, but skip for now
                        // Still need to count it? We'll just move on.
                        idx++; // optionally increment to keep count
                    }
                }
                out->dlls[out->count].func_count = idx;
            }
        }
        out->count++;
        offset += sizeof(IMPORT_DESCRIPTOR);
    }

    return 0;
}