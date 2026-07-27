#ifndef SECURITY_H
#define SECURITY_H
#include "pe.h"

// Returns 1 if [offset, offset+size) lies entirely within the file buffer.
// offset must be non-negative; size is the struct/data size being read.
int pe_bounds_ok(PEFile *pe, long offset, size_t size);

// Returns 1 if count is within a sane upper bound for this kind of table.
// Used to reject files claiming implausible section/import/export counts.
int pe_count_plausible(unsigned int count, unsigned int max_allowed);

// Copies a string out of the PE buffer at `offset`, safely capped so it
// never reads past the end of the file even without a null terminator.
// dest_size includes room for the null terminator. Returns 0 on success,
// 1 if offset is out of bounds.
int pe_safe_strcpy(PEFile *pe, long offset, char *dest, size_t dest_size);

#endif // SECURITY_H