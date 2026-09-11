"""Reconstructs the exfiltrated archive from the sealed pcap, end to end,
from a clean checkout. This is the single entry point for Objective 3 —
no manual terminal steps required to reproduce the recovered archive.

Usage: python3 recovered/recover.py
Reads:  original/evidence/network/incident.pcap
Writes: recovered/case-export.zip
        recovered/extracted/  (unzipped contents)
        recovered/recovery-report.json
"""
import csv
import hashlib
import json
import subprocess
import sys
import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PCAP_PATH = PROJECT_ROOT / "original" / "evidence" / "network" / "incident.pcap"
WORK_DIR = PROJECT_ROOT / "working" / "zeek-recover"
RECOVERED_DIR = PROJECT_ROOT / "recovered"
ZEEK_SCRIPT = PROJECT_ROOT / "scripts" / "extract-files.zeek"


def run_zeek():
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    (WORK_DIR / "extracted-files").mkdir(exist_ok=True)
    subprocess.run(
        ["zeek", "-C", "-r", str(PCAP_PATH), str(ZEEK_SCRIPT)],
        cwd=WORK_DIR, check=True,
    )


def find_zip_extraction():
    """Reads files.log to find the entry with mime_type application/zip,
    then locates the corresponding extracted file on disk by its fuid —
    no hardcoded filename."""
    sys.path.insert(0, str(PROJECT_ROOT / "timeline-builder"))
    from parsers.zeek import read_zeek_tsv

    files_log = WORK_DIR / "files.log"
    for _, row in read_zeek_tsv(str(files_log)):
        if row.get("mime_type") == "application/zip":
            fuid = row["fuid"]
            matches = list((WORK_DIR / "extracted-files").glob(f"*{fuid}*"))
            if not matches:
                raise FileNotFoundError(f"no extracted file found for fuid {fuid}")
            return matches[0], row
    raise ValueError("no application/zip entry found in files.log")


def count_csv_records(csv_bytes: bytes) -> dict:
    text = csv_bytes.decode("utf-8", errors="replace")
    reader = csv.reader(text.splitlines())
    rows = list(reader)
    header, data_rows = rows[0], rows[1:]
    return {"header": header, "data_row_count": len(data_rows), "total_row_count": len(rows)}


def main():
    run_zeek()
    zip_path, files_log_row = find_zip_extraction()

    RECOVERED_DIR.mkdir(exist_ok=True)
    final_zip_path = RECOVERED_DIR / "case-export.zip"
    final_zip_path.write_bytes(zip_path.read_bytes())

    zip_bytes = final_zip_path.read_bytes()
    zip_sha256 = hashlib.sha256(zip_bytes).hexdigest()

    extract_dir = RECOVERED_DIR / "extracted"
    extract_dir.mkdir(exist_ok=True)

    report = {
        "source_pcap": str(PCAP_PATH.relative_to(PROJECT_ROOT)),
        "files_log_locator": f"files.log fuid={files_log_row['fuid']}",
        "archive_path": str(final_zip_path.relative_to(PROJECT_ROOT)),
        "archive_sha256": zip_sha256,
        "archive_size_bytes": len(zip_bytes),
        "members": [],
    }

    with zipfile.ZipFile(final_zip_path) as zf:
        bad = zf.testzip()
        report["zip_integrity_ok"] = bad is None
        for info in zf.infolist():
            member_bytes = zf.read(info.filename)
            member_sha256 = hashlib.sha256(member_bytes).hexdigest()
            member_entry = {
                "filename": info.filename,
                "compressed_size": info.compress_size,
                "uncompressed_size": info.file_size,
                "sha256": member_sha256,
            }
            if info.filename.endswith(".csv"):
                member_entry["csv_record_counts"] = count_csv_records(member_bytes)
            report["members"].append(member_entry)
            (extract_dir / info.filename).write_bytes(member_bytes)

    report["file_count"] = len(report["members"])

    report_path = RECOVERED_DIR / "recovery-report.json"
    report_path.write_text(json.dumps(report, indent=2))

    print(f"\nWrote archive: {final_zip_path} ({len(zip_bytes)} bytes, sha256={zip_sha256})")
    print(f"Wrote report: {report_path}\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
