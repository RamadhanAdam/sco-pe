#ifndef IMPORTS_H
#define IMPORTS_H

#include "pe.h"

#define MAX_IMPORTED_DLLS   64
#define MAX_IMPORTED_FUNCS  256   // max functions per DLL

typedef struct {
    char name[256];                      // DLL name
    char funcs[MAX_IMPORTED_FUNCS][256]; // imported function names
    int  func_count;                     // how many functions from this DLL
} ImportedDLL;

typedef struct {
    ImportedDLL dlls[MAX_IMPORTED_DLLS];
    int count;
} ImportTable;

int parse_imports(PEFile *pe, ImportTable *out);

#endif