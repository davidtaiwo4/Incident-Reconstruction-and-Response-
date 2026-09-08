"""Parser for the sysmon.jsonl evidence source.

Adapts raw lines into schema.NormalizedEvent. Deliberately schema-agnostic:
does not special-case any particular event_type, computer, or binding value.
Anything not mapped to a named field is preserved in `extra` so nothing is
silently dropped.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from schema import NormalizedEvent
from classify import parse_json_line

CORE_FIELDS = {"computer", "event_id", "event_type",
               "schema_version", "timestamp", "user"}


def parse_line(raw_line: str, line_number: int, source_filename: str = "sysmon.jsonl"):
    """Returns (NormalizedEvent | None, status: str)."""
    parsed = parse_json_line(raw_line)
    if parsed["verdict"] == "quarantine":
        return None, "quarantined"

    rec = parsed["record"]
    raw_locator = f"{source_filename}:{line_number}"

    extra = {k: v for k, v in rec.items() if k not in CORE_FIELDS}

    event = NormalizedEvent(
        source="sysmon",
        raw_locator=raw_locator,
        event_type=rec.get("event_type"),
        original_timestamp=rec.get("timestamp"),
        normalized_timestamp_utc=rec.get("timestamp"),  # revisit once a clock offset is confirmed for this source
        host=rec.get("computer"),
        identity=rec.get("user"),
        parser_status="ok",
        extra=extra,
    )
    return event, "ok"


def parse_file(path: str):
    """Yields (NormalizedEvent | None, status) for every line in the file."""
    with open(path) as f:
        for i, line in enumerate(f, start=1):
            yield parse_line(line, i, source_filename=Path(path).name)
