import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "timeline-builder"))
from parsers.powershell import parse_line

KNOWN_EVENT_LINE = (
    '{"event_id": 4104, "timestamp": "2099-01-01T00:00:00Z", '
    '"script_name": "test.ps1", "script_block": "Write-Host test", '
    '"binding": "test-binding-0000"}'
)

UNKNOWN_EVENT_LINE = (
    '{"event_id": 9999, "timestamp": "2099-01-01T00:00:01Z", '
    '"script_name": "other.ps1", "script_block": "x"}'
)

MALFORMED_LINE = "{not valid json"


def test_known_event_id_classified():
    event, status = parse_line(KNOWN_EVENT_LINE, 1)
    assert status == "ok"
    assert event.event_type == "script_block_logging"
    assert event.host is None
    assert event.identity is None
    assert event.extra["binding"] == "test-binding-0000"


def test_unknown_event_id_falls_back():
    event, status = parse_line(UNKNOWN_EVENT_LINE, 2)
    assert event.event_type == "unknown"


def test_malformed_line_quarantined():
    event, status = parse_line(MALFORMED_LINE, 3)
    assert status == "quarantined"
    assert event is None
