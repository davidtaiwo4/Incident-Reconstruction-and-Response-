"""Assembles timeline.csv from all parsed evidence sources.

Deterministic: same inputs always produce the same output rows in the same
order. Clock correction applied once it is confirmed, the correction
hook below is where it gets applied.
"""
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from classify import validate_output_event
from parsers import email as email_parser
from parsers import powershell as powershell_parser
from parsers import sysmon as sysmon_parser
from parsers import zeek as zeek_parser

FIELDNAMES = [
    "source", "raw_locator", "event_type", "original_timestamp",
    "normalized_timestamp_utc", "host", "identity", "correlation_id",
    "parser_status", "parser_note",
]

# Confirmed clock offsets go here once identified from evidence, e.g.:
# CLOCK_OFFSETS_SECONDS = {"sysmon": -3600}
CLOCK_OFFSETS_SECONDS = {"sysmon": -85609}


def apply_clock_offset(event):
    offset = CLOCK_OFFSETS_SECONDS.get(event.source)
    if offset and event.normalized_timestamp_utc:
        from datetime import datetime, timedelta
        dt = datetime.fromisoformat(event.normalized_timestamp_utc.replace("Z", "+00:00"))
        corrected = dt + timedelta(seconds=offset)
        event.normalized_timestamp_utc = corrected.isoformat().replace("+00:00", "Z")
        event.parser_note = f"clock corrected by {offset}s"
    return event


def collect_events(evidence_root: str):
    events = []
    quarantined = 0

    for event, status in sysmon_parser.parse_file(f"{evidence_root}/host/sysmon.jsonl"):
        if status != "ok":
            quarantined += 1
            continue
        events.append(apply_clock_offset(event))

    for event, status in powershell_parser.parse_file(f"{evidence_root}/host/powershell-operational.jsonl"):
        if status != "ok":
            quarantined += 1
            continue
        events.append(apply_clock_offset(event))

    for event, status in email_parser.parse_file(f"{evidence_root}/mail/initial-access.eml"):
        if status != "ok":
            quarantined += 1
            continue
        events.append(apply_clock_offset(event))

    for logname, logtype in [("conn.log", "conn"), ("http.log", "http"), ("files.log", "files")]:
        path = f"working/zeek-logs/{logname}"
        if not Path(path).exists():
            continue
        for event, status in zeek_parser.parse_file(path, log_type=logtype):
            if status != "ok":
                quarantined += 1
                continue
            events.append(apply_clock_offset(event))

    return events, quarantined


def write_timeline_csv(events, output_path: str):
    def sort_key(event):
        # Events with no timestamp (e.g. the eml) sort first, deterministically.
        return (event.normalized_timestamp_utc or "", event.raw_locator)

    events_sorted = sorted(events, key=sort_key)

    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        for event in events_sorted:
            row = {k: getattr(event, k) for k in FIELDNAMES}
            source_locator_check = validate_output_event({"source_locator": event.raw_locator})
            if source_locator_check["verdict"] != "ok":
                raise ValueError(f"event failed locator validation: {event}")
            writer.writerow(row)

    return len(events_sorted)


if __name__ == "__main__":
    events, quarantined = collect_events("original/evidence")
    count = write_timeline_csv(events, "timeline-builder/timeline.csv")
    print(f"wrote {count} events to timeline-builder/timeline.csv")
    print(f"quarantined: {quarantined}")
