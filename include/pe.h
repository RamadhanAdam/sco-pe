// Declares the PEFile struct and top-level parsing API

#ifndef PE_H
#define PE_H

typedef struct {
    unsigned char *buffer;
    long size;
} PEFile;
#endif // PE_H
