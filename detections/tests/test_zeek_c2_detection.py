"""Runs the Zeek C2-domain detection against both a known-positive pcap
(the real sealed incident.pcap) and a known-negative synthetic pcap,
confirming the rule fires on one and not the other.
"""
import subprocess
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
ZEEK_SCRIPT = PROJECT_ROOT / "detections" / "zeek" / "detect-c2-domain.zeek"
POSITIVE_PCAP = PROJECT_ROOT / "original" / "evidence" / "network" / "incident.pcap"
NEGATIVE_PCAP = PROJECT_ROOT / "detections" / "tests" / "fixtures" / "benign-traffic.pcap"


def run_zeek_and_read_notices(pcap_path: Path) -> str:
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(
            ["zeek", "-C", "-r", str(pcap_path), str(ZEEK_SCRIPT)],
            cwd=tmp, check=True,
        )
        notice_path = Path(tmp) / "notice.log"
        if not notice_path.exists():
            return ""
        return notice_path.read_text()


def test_positive_pcap_triggers_c2_notice():
    notices = run_zeek_and_read_notices(POSITIVE_PCAP)
    assert "C2_Domain_Contacted" in notices


def test_negative_pcap_does_not_trigger_c2_notice():
    notices = run_zeek_and_read_notices(NEGATIVE_PCAP)
    assert "C2_Domain_Contacted" not in notices
