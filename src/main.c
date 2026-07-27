// Entry point: calls each parsing step in order, then prints a report
#include <stdio.h>
#include "pe.h"
#include "file.h"
#include "dos.h"
#include "nt.h"
#include "sections.h"
#include "imports.h"
#include "exports.h"

int main(void) {
    PEFile pe;
    const char *target = "samples/putty.exe";

    printf("========================================\n");
    printf(" sco-pe - PE File Parser\n");
    printf("========================================\n");
    printf("Target: %s\n\n", target);

    if (pe_open(target, &pe) != 0) {
        printf("Failed to open file\n");
        return 1;
    }

    if (parse_dos_header(&pe) != 0) {
        printf("Failed to parse DOS header\n");
        pe_close(&pe);
        return 1;
    }

    if (parse_nt_headers(&pe) != 0) {
        printf("Failed to parse NT headers\n");
        pe_close(&pe);
        return 1;
    }

    if (parse_sections(&pe) != 0) {
        printf("Failed to parse sections\n");
        pe_close(&pe);
        return 1;
    }

    ImportTable imports;
    if (parse_imports(&pe, &imports) != 0) {
        printf("Failed to parse imports\n");
        pe_close(&pe);
        return 1;
    }

    ExportTable exports;
    if (parse_exports(&pe, &exports) != 0) {
        printf("Failed to parse exports\n");
        pe_close(&pe);
        return 1;
    }

    printf("[ File ]\n");
    printf("  %-20s %ld bytes\n", "Size:", pe.size);

    printf("\n[ DOS Header ]\n");
    printf("  %-20s 0x%X\n", "e_lfanew:", pe.dos_header->e_lfanew);

    printf("\n[ NT Headers ]\n");
    printf("  %-20s %u\n", "Sections:", pe.nt_headers->file_header.number_of_sections);
    printf("  %-20s 0x%X\n", "Magic:", pe.nt_headers->optional_header.magic);

    printf("\n[ Sections ]\n");
    for (int i = 0; i < pe.nt_headers->file_header.number_of_sections; i++) {
        printf("  %-10.8s VA: 0x%-8X RawSize: 0x%X\n",
               pe.sections[i].name,
               pe.sections[i].virtual_address,
               pe.sections[i].size_of_raw_data);
    }

    printf("\n[ Imports ] (%d DLLs)\n", imports.count);
    for (int i = 0; i < imports.count; i++) {
        printf("  %s\n", imports.dlls[i].name);
    }

    printf("\n[ Exports ] (%d functions)\n", exports.count);
    if (exports.dll_name[0] != '\0') {
        printf("  DLL: %s\n", exports.dll_name);
    }
    for (int i = 0; i < exports.count; i++) {
        printf("  %s\n", exports.funcs[i].name);
    }

    pe_close(&pe);
    printf("\n========================================\n");
    printf(" Done.\n");
    printf("========================================\n");

    return 0;
}