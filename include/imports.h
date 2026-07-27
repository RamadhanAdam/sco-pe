// Declares the import table parsing function

#ifndef IMPORTS_H
#define IMPORTS_H
#include "pe.h"

// Preventing buffer allocation overflows by imposing a safe hard boundary
#define MAX_IMPORTED_DLLS 64

typedef struct {
    char name[256]; // Maximum filename length storoage (matches Windows API specs)

} ImportedDLL;

typedef struct {
    ImportedDLL dlls[MAX_IMPORTED_DLLS];
    int count; // Total number of valid dynamic libraries extracted
} ImportTable;

// Entrypoint wrapper to extract dependency listings out of parsed PE image context
int parse_imports(PEFile *pe, ImportTable *out);

#endif // IMPORTS_H
