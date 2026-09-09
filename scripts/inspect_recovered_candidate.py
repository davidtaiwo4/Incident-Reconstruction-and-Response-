"""Generic inspection of a recovered binary candidate: hash, size, magic
bytes, and if it's actually a zip its internal file list and per-entry
sizes. Makes no claim about whether this IS the exfiltrated archive; that
determination and its evidence chain belong in evidence-index.csv.

Usage: python3 scripts/inspect_recovered_candidate.py <path>
"""
import hashlib
import sys
import zipfile
from pathlib import Path

def main():
    path = Path(sys.argv[1])
    data = path.read_bytes()

    print(f"file: {path}")
    print(f"size: {len(data)} bytes")
    print(f"sha256: {hashlib.sha256(data).hexdigest()}")
    print(f"first 16 bytes (hex): {data[:16].hex()}")
    print(f"first 4 bytes (magic): {data[:4]!r}")

    if data[:4] == b'PK\x03\x04' or data[:4] == b'PK\x05\x06':
        print()
        print("--- looks like a zip archive; listing contents ---")
        try:
            with zipfile.ZipFile(path) as zf:
                bad_entry = zf.testzip()
                print(f"zip integrity check (testzip): {'OK' if bad_entry is None else f'FAILED at {bad_entry}'}")
                for info in zf.infolist():
                    print(f"  {info.filename:40s} compressed={info.compress_size:>10} uncompressed={info.file_size:>10}")
        except zipfile.BadZipFile as e:
            print(f"zipfile could not open it: {e}")
    else:
        print()
        print("does not start with a zip magic number — not a valid zip as-is")

if __name__ == "__main__":
    main()
