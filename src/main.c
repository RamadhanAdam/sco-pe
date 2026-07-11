// Entry point: calls each parsing step in order, then prints a report
#include <stdio.h>
#include "pe.h"
#include "file.h"

int main(void) {
    PEFile pe;

    // Open the file and read its bytes into pe.buffer
    if (pe_open("samples/putty.exe", &pe) != 0) {
        printf("Failed to open file\n");
        return 1;
    }

    printf("Opened file. Size: %ld bytes\n", pe.size);

    // Free the memory once we're done
    pe_close(&pe);

    return 0;
}