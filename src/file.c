// Opens the file, reads the raw bytes into memory, closes it when done
#include <stdio.h>
#include <stdlib.h>
#include "file.h"
#include "pe.h"

int pe_open(const char *filename, PEFile *pe){
    FILE *f = fopen(filename, "rb");
    if (f == NULL){
        printf("Error: could not open file %s\n", filename);
        return 1;
    }

    // Jump to end of file
    fseek(f, 0, SEEK_END);
    long size = ftell(f);

    if (size <= 0){
        printf("Error: could not determine file size for %s\n", filename);
        fclose(f);
        return 1;
    }
    // Moving pointer to start
    fseek(f, 0, SEEK_SET);

    // Allocating memory

    unsigned char* buffer = malloc(size);
    if (buffer == NULL){
        printf("Error: could not allocate memory for %s\n", filename);
        fclose(f);
        return 1;
    }

    // Reading file
    fread(buffer, size, 1, f);

    // Storing into the struct, and closing
    pe->buffer = buffer;
    pe->size = size;
    fclose(f);

    return 0;
}

void pe_close(PEFile *pe){
    // Freeing the memory
    free(pe->buffer);
    pe->buffer = NULL;
}