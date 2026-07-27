# tools/overlay_extract.py
# Extracts any data appended after the last PE section (the "overlay"),
# commonly used by malware to hide payloads. Skips the Authenticode
# signature block if present, since it also lives past the last section.

import sys
import pefile

def extract_overlay(exe_path, output_path):
    print(f"[*] Opening: {exe_path}")

    try:
        pe = pefile.PE(exe_path, fast_load=True)

        # Headers end here (DOS header + PE headers + optional header)
        headers_end = pe.OPTIONAL_HEADER.SizeOfHeaders

        # Find where last section ends on disk
        sections_end = 0
        for section in pe.sections:
            section_end = section.PointerToRawData + section.SizeOfRawData
            if section_end > sections_end:
                sections_end = section_end

        # PE ends at whichever is larger (guards against packed/odd PEs
        # with missing or zero sections)
        pe_end_offset = max(headers_end, sections_end)
        print(f"[+] PE ends at byte: {pe_end_offset}")

        # Authenticode signature also sits after the last section on disk,
        # so it looks like overlay if we don't account for it
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
        if sec_dir.VirtualAddress != 0:
            sig_start = sec_dir.VirtualAddress
            print(f"[!] Digital signature found at byte {sig_start}, size {sec_dir.Size}")
            pe_end_offset = max(pe_end_offset, sig_start + sec_dir.Size)

        with open(exe_path, "rb") as f:
            f.seek(0, 2)
            total_size = f.tell()

            if total_size <= pe_end_offset:
                print("[-] No overlay found")
                pe.close()
                return

            overlay_size = total_size - pe_end_offset
            print(f"[+] Overlay size: {overlay_size} bytes")

            f.seek(pe_end_offset)
            overlay_data = f.read()

        with open(output_path, "wb") as out:
            out.write(overlay_data)
        print(f"[+] Saved to: {output_path}")

        pe.close()

    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python overlay_extract.py <file.exe> <output.bin>")
        sys.exit(1)
    extract_overlay(sys.argv[1], sys.argv[2])