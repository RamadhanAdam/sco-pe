#ifndef SECURITY_H
#define SECURITY_H

#include <stddef.h> // Fixed: Required definition for size_t
#include "pe.h"

/**
 * @brief Checks if the memory range [offset, offset + size) fits within the file buffer.
 * @return 1 if valid, 0 if out of bounds.
 */
int pe_bounds_ok(PEFile *pe, long offset, size_t size);

/**
 * @brief Ensures table counts are within acceptable limits to reject malformed files.
 * @return 1 if plausible, 0 if suspicious.
 */
int pe_count_plausible(unsigned int count, unsigned int max_allowed);

/**
 * @brief Copies an ASCII string from the PE buffer safely, guaranteeing null-termination.
 * @return 0 on success, 1 on out-of-bounds error.
 */
int pe_safe_strcpy(PEFile *pe, long offset, char *dest, size_t dest_size);

#endif // SECURITY_H
