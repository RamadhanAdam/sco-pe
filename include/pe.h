// Declares the PEFile struct and top-level parsing API

#ifndef PE_H
#define PE_H

// Minimal DOS header - only the two fields we actually use
typedef struct {
    unsigned short e_magic;      // 2 bytes, offset 0x00 - should be "MZ" (0x5A4D)
    unsigned char  reserved[58]; // padding, offset 0x02 to 0x3B, unused
    unsigned int   e_lfanew;     // 4 bytes, offset 0x3C - offset to NT headers
} DOS_HEADER;

// Minimal File Header - every field is present since they're all small
// and cheap to keep for context, even ones we don't use yet
typedef struct {
    unsigned short machine;                 // target CPU type
    unsigned short number_of_sections;      // how many section table entries follow
    unsigned int   time_date_stamp;         // build timestamp, unused for now
    unsigned int   pointer_to_symbol_table; // deprecated, unused
    unsigned int   number_of_symbols;       // deprecated, unused
    unsigned short size_of_optional_header; // size of the optional header that follows
    unsigned short characteristics;         // flags (executable, DLL, etc.)
} FILE_HEADER;

// Minimal Optional Header - only magic and size_of_headers matter right now.
// reserved[58] skips everything between them so size_of_headers lands
// at the correct real offset (0x3C) when we cast raw bytes onto this struct
typedef struct {
    unsigned short magic;           // 0x10b = PE32, 0x20b = PE32+
    unsigned char  reserved[58];    // padding, unused fields between magic and size_of_headers
    unsigned int   size_of_headers; // combined size of all headers
} OPTIONAL_HEADER;

// PE signature + File Header + Optional Header
typedef struct {
    unsigned int    signature;      // should be "PE\0\0" (0x00004550)
    FILE_HEADER     file_header;
    OPTIONAL_HEADER optional_header;
} NT_HEADERS;

// Holds everything discovered about a PE file as parsing proceeds
typedef struct {
    unsigned char *buffer;        // raw file bytes
    long size;                    // number of bytes in buffer
    DOS_HEADER *dos_header;       // points into buffer, filled in by dos.c
    NT_HEADERS *nt_headers;       // points into buffer, filled in by nt.c
} PEFile;

#endif // PE_H