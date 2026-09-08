import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "timeline-builder"))
from parsers.sysmon import parse_line

BASELINE_LINE = (
    '{"schema_version": "1", "event_id": "test-0001", '
    '"timestamp": "2099-01-01T00:00:00Z", "computer": "TEST-HOST", '
    '"user": "test\\\\user", "event_type": "process_start", '
    '"image": "notepad.exe", "parent_image": "explorer.exe", "detail": "x"}'
)

EXTENDED_LINE = (
    '{"schema_version": "2", "event_id": "test-0002", '
    '"timestamp": "2099-01-01T00:00:01Z", "computer": "TEST-HOST", '
    '"user": "test\\\\user", "event_type": "file_delete", '
    '"image": "cmd.exe", "parent_image": "cmd.exe", "detail": "x", '
    '"evidence_binding": "test-binding-0000", "marker": null}'
)

MALFORMED_LINE = "{not valid json"


def test_baseline_schema_parses():
    event, status = parse_line(BASELINE_LINE, 1)
    assert status == "ok"
    assert event.host == "TEST-HOST"
    assert event.identity == "test\\user"
    assert event.event_type == "process_start"
    assert event.raw_locator == "sysmon.jsonl:1"
    assert event.extra == {"image": "notepad.exe", "parent_image": "explorer.exe", "detail": "x"}


def test_extended_schema_preserves_binding_in_extra():
    event, status = parse_line(EXTENDED_LINE, 2)
    assert status == "ok"
    assert event.extra["evidence_binding"] == "test-binding-0000"
    assert event.extra["marker"] is None


def test_malformed_line_is_quarantined_not_dropped_silently():
    event, status = parse_line(MALFORMED_LINE, 3)
    assert status == "quarantined"
    assert event is None
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "timeline-builder"))
from parsers.sysmon import parse_line

BASELINE_LINE = (
    '{"schema_version": "1", "event_id": "test-0001", '
    '"timestamp": "2099-01-01T00:00:00Z", "computer": "TEST-HOST", '
    '"user": "test\\\\user", "event_type": "process_start", '
    '"image": "notepad.exe", "parent_image": "explorer.exe", "detail": "x"}'
)

EXTENDED_LINE = (
    '{"schema_version": "2", "event_id": "test-0002", '
    '"timestamp": "2099-01-01T00:00:01Z", "computer": "TEST-HOST", '
    '"user": "test\\\\user", "event_type": "file_delete", '
    '"image": "cmd.exe", "parent_image": "cmd.exe", "detail": "x", '
    '"evidence_binding": "test-binding-0000", "marker": null}'
)

MALFORMED_LINE = "{not valid json"


def test_baseline_schema_parses():
    event, status = parse_line(BASELINE_LINE, 1)
    assert status == "ok"
    assert event.host == "TEST-HOST"
    assert event.identity == "test\\user"
    assert event.event_type == "process_start"
    assert event.raw_locator == "sysmon.jsonl:1"
    assert event.extra == {"image": "notepad.exe", "parent_image": "explorer.exe", "detail": "x"}


def test_extended_schema_preserves_binding_in_extra():
    event, status = parse_line(EXTENDED_LINE, 2)
    assert status == "ok"
    assert event.extra["evidence_binding"] == "test-binding-0000"
    assert event.extra["marker"] is None


def test_malformed_line_is_quarantined_not_dropped_silently():
    event, status = parse_line(MALFORMED_LINE, 3)
    assert status == "quarantined"
    assert event is None
