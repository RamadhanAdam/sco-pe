// Declares the RVA-to-offset conversion function

#ifndef UTILS_H
#define UTILS_H
#include "pe.h"

// Converts a Relative Virtual Address to a file offset by finding which section
// contains it. Returns -1 if not found.
long rva_to_offset(PEFile *pe, unsigned int rva);

#endif // UTILS_H
