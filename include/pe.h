// Declares the PEFile struct and top-level parsing API

#ifndef PE_H
#define PE_H

// DOS header - only fields we use, rest is padding
typedef struct {
    unsigned short e_magic;      // "MZ" (0x5A4D)
    unsigned char  reserved[58];
    unsigned int   e_lfanew;     // offset to NT headers
} DOS_HEADER;

// COFF file header
typedef struct {
    unsigned short machine;
    unsigned short number_of_sections;
    unsigned int   time_date_stamp;
    unsigned int   pointer_to_symbol_table; // deprecated
    unsigned int   number_of_symbols;       // deprecated
    unsigned short size_of_optional_header;
    unsigned short characteristics;
} FILE_HEADER;

// RVA/size pair
typedef struct {
    unsigned int virtual_address;
    unsigned int size;
} DATA_DIRECTORY;

// Indices into optional_header.data_directory[]
#define DIR_EXPORT   0
#define DIR_IMPORT   1
#define DIR_SECURITY 4

// Optional header (PE32+). reserved/reserved2 preserve real byte offsets.
typedef struct {
    unsigned short magic;              // 0x20b = PE32+
    unsigned char  reserved[58];
    unsigned int   size_of_headers;
    unsigned char  reserved2[48];
    DATA_DIRECTORY data_directory[16]; // export, import, resource, security, etc.
} OPTIONAL_HEADER;

// PE signature + File Header + Optional Header
typedef struct {
    unsigned int    signature;  // "PE\0\0" (0x00004550)
    FILE_HEADER     file_header;
    OPTIONAL_HEADER optional_header;
} NT_HEADERS;

// Everything discovered about a PE file as parsing proceeds
typedef struct {
    unsigned char *buffer;
    long size;
    DOS_HEADER *dos_header;
    NT_HEADERS *nt_headers;
} PEFile;

#endif // PE_H