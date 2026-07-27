// Complile using - gcc overlay.c -o overlay.exe -lversion (or just gcc overlay.c -o overlay.exe)
// Author: Ramadhan Adam Zome, @27.7.2026

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: overlay.exe <input.exe> <output.bin>\n");
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        printf("[-] Cannot open file\n");
        return 1;
    }

    // Read DOS header
    IMAGE_DOS_HEADER dos;
    fread(&dos, sizeof(dos), 1, f);

    // Check MZ signature
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Not a valid DOS/PE file\n");
        fclose(f);
        return 1;
    }

    // Jump to PE header using e_lfanew
    fseek(f, dos.e_lfanew, SEEK_SET);
    IMAGE_NT_HEADERS nt;
    fread(&nt, sizeof(nt), 1, f);

    // Check PE signature
    if (nt.Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Not a valid PE file\n");
        fclose(f);
        return 1;
    }

    // This reads IMAGE_NT_HEADERS64 (PE32+) since we compile for x64.
    // A 32-bit PE has a different OptionalHeader layout/size, so check Magic.
    if (nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        printf("[-] Only 64-bit PE files are supported\n");
        fclose(f);
        return 1;
    }

    // Find last section end
    uint32_t pe_end = nt.OptionalHeader.SizeOfHeaders;
    for (int i = 0; i < nt.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sec;
        fread(&sec, sizeof(sec), 1, f);
        uint32_t sec_end = sec.PointerToRawData + sec.SizeOfRawData;
        if (sec_end > pe_end) pe_end = sec_end;
    }

    // Digital signature also sits after the last section on disk,
    // so it looks like overlay if we don't account for it
    IMAGE_DATA_DIRECTORY sec_dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    if (sec_dir.VirtualAddress != 0) {
        uint32_t sig_end = sec_dir.VirtualAddress + sec_dir.Size;
        printf("[!] Digital signature found at byte %u, size %u\n", sec_dir.VirtualAddress, sec_dir.Size);
        if (sig_end > pe_end) pe_end = sig_end;
    }

    // Get file size
    fseek(f, 0, SEEK_END);
    uint32_t file_size = ftell(f);

    if (file_size <= pe_end) {
        printf("[-] No overlay\n");
        fclose(f);
        return 1;
    }

    // Extract overlay
    uint32_t overlay_size = file_size - pe_end;
    printf("[+] Overlay size: %u bytes\n", overlay_size);

    fseek(f, pe_end, SEEK_SET);
    uint8_t *overlay = malloc(overlay_size);
    if (!overlay) {
        printf("[-] malloc failed\n");
        fclose(f);
        return 1;
    }
    if (fread(overlay, overlay_size, 1, f) != 1) {
        printf("[-] Failed to read overlay data\n");
        free(overlay);
        fclose(f);
        return 1;
    }
    fclose(f);

    // Write overlay
    FILE *out = fopen(argv[2], "wb");
    if (!out) {
        printf("[-] Cannot open output file\n");
        free(overlay);
        return 1;
    }
    fwrite(overlay, overlay_size, 1, out);
    fclose(out);

    printf("[+] Saved to %s\n", argv[2]);
    free(overlay);
    return 0;
}