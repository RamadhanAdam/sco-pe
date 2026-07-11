#include <stdio.h>
#include "pe.h"
#include "file.h"

int main(void) {
    PEFile pe;
    int result = pe_open("samples/putty.exe", &pe);

    if (result != 0) {
        printf("FAIL: pe_open returned failure\n");
        return 1;
    }

    if (pe.size != 1708656) {
        printf("FAIL: expected size 1708656, got %ld\n", pe.size);
        return 1;
    }

    printf("PASS: file.c opened putty.exe correctly, size = %ld\n", pe.size);

    pe_close(&pe);
    return 0;
}
