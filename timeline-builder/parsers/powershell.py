"""Parser for the powershell-operational.jsonl evidence source.

Unlike sysmon, this source has no host/identity fields — that absence is
preserved (host=None, identity=None) rather than guessed at.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from schema import NormalizedEvent
from classify import parse_json_line

CORE_FIELDS = {"event_id", "timestamp"}

# Real Microsoft-Windows-PowerShell/Operational event IDs (public documentation,
# not case-specific): 4104 = script block logging (execution of a script block).
EVENT_ID_MAP = {
    4104: "script_block_logging",
}


def parse_line(raw_line: str, line_number: int, source_filename: str = "powershell-operational.jsonl"):
    parsed = parse_json_line(raw_line)
    if parsed["verdict"] == "quarantine":
        return None, "quarantined"

    rec = parsed["record"]
    raw_locator = f"{source_filename}:{line_number}"
    extra = {k: v for k, v in rec.items() if k not in CORE_FIELDS}

    event = NormalizedEvent(
        source="powershell",
        raw_locator=raw_locator,
        event_type=EVENT_ID_MAP.get(rec.get("event_id"), "unknown"),
        original_timestamp=rec.get("timestamp"),
        normalized_timestamp_utc=rec.get("timestamp"),  # revisit once a clock offset is confirmed for this source
        host=None,
        identity=None,
        parser_status="ok",
        extra=extra,
    )
    return event, "ok"


def parse_file(path: str):
    with open(path) as f:
        for i, line in enumerate(f, start=1):
            yield parse_line(line, i, source_filename=Path(path).name)
