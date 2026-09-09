import json
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from recovered.recover import main as run_recover

RECOVERED_DIR = Path(__file__).resolve().parent.parent / "recovered"


def test_recover_produces_valid_zip_and_report():
    run_recover()

    zip_path = RECOVERED_DIR / "case-export.zip"
    assert zip_path.exists()

    with zipfile.ZipFile(zip_path) as zf:
        assert zf.testzip() is None  # zip integrity check passes

    report_path = RECOVERED_DIR / "recovery-report.json"
    report = json.loads(report_path.read_text())

    assert report["zip_integrity_ok"] is True
    assert report["file_count"] == len(report["members"])
    assert all(len(m["sha256"]) == 64 for m in report["members"])
