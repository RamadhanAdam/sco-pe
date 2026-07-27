// Test for dos.c: confirms parse_dos_header reads a real DOS header correctly
// Run with: gcc -Iinclude tests/dos_test.c src/file.c src/dos.c -o bin/dos_test && ./bin/dos_test
#include <stdio.h>
#include "pe.h"
#include "file.h"
#include "dos.h"

int main(void) {
    PEFile pe;

    if (pe_open("samples/putty.exe", &pe) != 0) {
        printf("FAIL: pe_open returned failure\n");
        return 1;
    }

    if (parse_dos_header(&pe) != 0) {
        printf("FAIL: parse_dos_header returned failure\n");
        pe_close(&pe);
        return 1;
    }

    if (pe.dos_header->e_lfanew != 0x78) {
        printf("FAIL: expected e_lfanew 0x78, got 0x%X\n", pe.dos_header->e_lfanew);
        pe_close(&pe);
        return 1;
    }

    printf("PASS: DOS header parsed. e_lfanew = 0x%X\n", pe.dos_header->e_lfanew);

    pe_close(&pe);
    return 0;
}