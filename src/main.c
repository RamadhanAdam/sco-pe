#include <stdio.h>
#include <string.h>
#include "pe.h"
#include "file.h"
#include "dos.h"
#include "nt.h"
#include "sections.h"
#include "imports.h"
#include "exports.h"

#define DIR_SECURITY 4

static const char* arch(unsigned short m) {
    if (m == 0x14C)  return "x86";
    if (m == 0x8664) return "x64";
    if (m == 0xAA64) return "ARM64";
    return "Unknown";
}

static void perm_str(unsigned int flags, char *out) {
    out[0] = (flags & 0x40000000) ? 'R' : '-';
    out[1] = (flags & 0x80000000) ? 'W' : '-';
    out[2] = (flags & 0x20000000) ? 'X' : '-';
    out[3] = '\0';
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <file>\n", argv[0]);
        return 1;
    }

    PEFile pe;
    if (pe_open(argv[1], &pe) != 0) {
        printf("Error: cannot open %s\n", argv[1]);
        return 1;
    }
    if (parse_dos_header(&pe) || parse_nt_headers(&pe) || parse_sections(&pe)) {
        printf("Error: parse failed\n");
        pe_close(&pe);
        return 1;
    }

    ImportTable imports = {0};
    ExportTable exports = {0};
    parse_imports(&pe, &imports);
    parse_exports(&pe, &exports);

    // Overlay detection
    unsigned int pe_end = pe.nt_headers->optional_header.size_of_headers;
    unsigned short sec_count = pe.nt_headers->file_header.number_of_sections;
    for (int i = 0; i < sec_count; i++) {
        unsigned int sec_end = pe.sections[i].pointer_to_raw_data + pe.sections[i].size_of_raw_data;
        if (sec_end > pe_end) pe_end = sec_end;
    }
    DATA_DIRECTORY sec_dir = pe.nt_headers->optional_header.data_directory[DIR_SECURITY];
    if (sec_dir.virtual_address != 0 && sec_dir.size != 0) {
        unsigned int sig_end = sec_dir.virtual_address + sec_dir.size;
        if (sig_end > pe_end) pe_end = sig_end;
    }
    long overlay = (pe.size > (long)pe_end) ? (pe.size - (long)pe_end) : 0;

    // ---- Report ----
    printf("\nsco-pe — PE File Parser\n");
    printf("Target: %s (%ld bytes)\n\n", argv[1], pe.size);

    printf("[Summary]\n");
    printf("  Architecture:  %s\n", arch(pe.nt_headers->file_header.machine));
    printf("  Magic:         0x%X\n", pe.nt_headers->optional_header.magic);
    printf("  Sections:      %u\n", sec_count);
    printf("  Overlay:       %s\n", overlay > 0 ? "YES (appended data)" : "none");
    if (overlay > 0) printf("  Overlay size:  %ld bytes\n", overlay);
    printf("\n");

    printf("[Sections]\n");
    printf("  %-10s %-12s %-12s %-12s %s\n", "Name", "VirtAddr", "VirtSize", "RawSize", "Perms");
    for (int i = 0; i < sec_count; i++) {
        char name[9] = {0};
        strncpy(name, pe.sections[i].name, 8);
        char perms[4];
        perm_str(pe.sections[i].characteristics, perms);
        printf("  %-10s 0x%-10X 0x%-10X 0x%-10X %s\n",
               name,
               pe.sections[i].virtual_address,
               pe.sections[i].virtual_size,
               pe.sections[i].size_of_raw_data,
               perms);
    }

    printf("\n[Imports] (%d DLLs)\n", imports.count);
    for (int i = 0; i < imports.count; i++) {
        printf("  %s (%d functions)\n", imports.dlls[i].name, imports.dlls[i].func_count);
        for (int j = 0; j < imports.dlls[i].func_count; j++) {
            printf("    └── %s\n", imports.dlls[i].funcs[j]);
        }
    }

    printf("\n[Exports] (%d functions)\n", exports.count);
    if (exports.dll_name[0]) printf("  DLL: %s\n", exports.dll_name);
    for (int i = 0; i < exports.count; i++) {
        printf("  %s\n", exports.funcs[i].name);
    }
    printf("\n");

    pe_close(&pe);
    return 0;
}