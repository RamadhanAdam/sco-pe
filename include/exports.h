#ifndef EXPORTS_H
#define EXPORTS_H
#include "pe.h"

// Define a stable upper limit to prevent memory space buffer overruns
#define MAX_EXPORTED_FUNCS 256

typedef struct {
    char name[256]; // Buffer allocation to store individual exported function names
} ExportedFunc;

typedef struct {
    char dll_name[256];                    // Container for the internal name of this DLL binary
    ExportedFunc funcs[MAX_EXPORTED_FUNCS]; // Static array holding function listing records
    int count;                             // Tracking counter for functions parsed
} ExportTable;

// Primary entrypoint to walk export metadata tables from an initialized PE file
int parse_exports(PEFile *pe, ExportTable *out);

#endif // EXPORTS_H
