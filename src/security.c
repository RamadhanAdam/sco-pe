// Shared bounds-checking and safe-copy helpers used by every parsing module.
// Centralizing these means every struct read and string extraction goes
// through the same validation instead of each .c file reimplementing it.
#include "security.h"
#include <string.h>

int pe_bounds_ok(PEFile *pe, long offset, size_t size) {
    if (offset < 0) return 0;
    if ((long)size < 0) return 0;
    if (offset + (long)size > pe->size) return 0;
    return 1;
}

int pe_count_plausible(unsigned int count, unsigned int max_allowed) {
    return count <= max_allowed;
}

int pe_safe_strcpy(PEFile *pe, long offset, char *dest, size_t dest_size) {
    if (offset < 0 || offset >= pe->size) {
        dest[0] = '\0';
        return 1;
    }

    long max_len = pe->size - offset;
    if (max_len > (long)dest_size - 1) {
        max_len = (long)dest_size - 1;
    }

    strncpy(dest, (char *)(pe->buffer + offset), max_len);
    dest[max_len] = '\0';
    return 0;
}
