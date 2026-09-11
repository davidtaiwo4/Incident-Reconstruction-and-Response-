"""Assembles the timeline.csv deliverable from all parsed evidence
sources, in the exact schema required by timeline.csv's template.

Deterministic: event_id is assigned by sorted position, never by an
external random value such as Zeek's uid. Analyst judgment columns
(attack_technique, confidence, primary_or_supporting, alternative_interpretation)
come ONLY from annotations.py, keyed by exact_locator — never fabricated
here. Rows with no matching annotation get honest defaults, not guesses.
"""
import csv
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from parsers import email as email_parser
from parsers import powershell as powershell_parser
from parsers import sysmon as sysmon_parser
from parsers import zeek as zeek_parser
from annotations import ANNOTATIONS

FIELDNAMES = [
    "event_id", "utc_time", "original_time", "source_timezone", "host",
    "user", "activity", "artifact_path", "exact_locator", "attack_technique",
    "confidence", "primary_or_supporting", "alternative_interpretation", "notes",
]

# Confirmed via 3 independent event-pair measurements — see decision-log D-003.
CLOCK_OFFSETS_SECONDS = {"sysmon": -85609}

ARTIFACT_PATHS = {
    "sysmon": "original/evidence/host/sysmon.jsonl",
    "powershell": "original/evidence/host/powershell-operational.jsonl",
    "eml": "original/evidence/mail/initial-access.eml",
    "zeek_conn": "working/zeek-logs/conn.log",
    "zeek_http": "working/zeek-logs/http.log",
    "zeek_files": "working/zeek-logs/files.log",
    "zeek_dns": "working/zeek-logs/dns.log",
}

SOURCE_TIMEZONE_NOTE = {
    "sysmon": "UTC (host clock corrected -85609s, see decision-log D-003)",
    "powershell": "UTC",
    "eml": "UTC (unknown — source has no Date header)",
    "zeek_conn": "UTC",
    "zeek_http": "UTC",
    "zeek_files": "UTC",
    "zeek_dns": "UTC",
}


def apply_clock_offset(event):
    offset = CLOCK_OFFSETS_SECONDS.get(event.source)
    if offset and event.normalized_timestamp_utc:
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


def format_activity(event) -> str:
    extra = event.extra
    if event.source == "sysmon":
        return f"{event.event_type}: {extra.get('image')} (parent: {extra.get('parent_image')}) — {extra.get('detail', '')}"
    if event.source == "powershell":
        block = (extra.get("script_block") or "")[:80]
        return f"{event.event_type}: {extra.get('script_name')} — {block}"
    if event.source == "eml":
        return f"email_delivery: from={extra.get('from')} to={event.identity} subject={extra.get('subject')}"
    if event.source == "zeek_conn":
        return (f"network_connection: {event.host}:{extra.get('id.orig_p')} -> "
                f"{extra.get('id.resp_h')}:{extra.get('id.resp_p')} "
                f"proto={extra.get('proto')} service={extra.get('service')}")
    if event.source == "zeek_http":
        return f"http_request: {extra.get('method')} {extra.get('host')}{extra.get('uri')} status={extra.get('status_code')}"
    if event.source == "zeek_files":
        return f"file_transfer: mime={extra.get('mime_type')} size={extra.get('seen_bytes')} bytes"
    return event.event_type or "unknown"


def build_report_rows(events):
    def sort_key(event):
        return (event.normalized_timestamp_utc or "", event.raw_locator)

    events_sorted = sorted(events, key=sort_key)
    rows = []

    for i, event in enumerate(events_sorted, start=1):
        annotation = ANNOTATIONS.get(event.raw_locator, {})

        note_parts = []
        if event.parser_note:
            note_parts.append(event.parser_note)
        if "notes_override" in annotation:
            note_parts.append(annotation["notes_override"])

        rows.append({
            "event_id": f"EV-{i:06d}",
            "utc_time": event.normalized_timestamp_utc or "",
            "original_time": event.original_timestamp or "",
            "source_timezone": SOURCE_TIMEZONE_NOTE.get(event.source, "UTC"),
            "host": event.host or "",
            "user": event.identity or "",
            "activity": format_activity(event),
            "artifact_path": ARTIFACT_PATHS.get(event.source, ""),
            "exact_locator": event.raw_locator,
            "attack_technique": annotation.get("attack_technique", ""),
            "confidence": annotation.get("confidence", ""),
            "primary_or_supporting": annotation.get("primary_or_supporting", "supporting"),
            "alternative_interpretation": annotation.get("alternative_interpretation", ""),
            "notes": "; ".join(note_parts),
        })
    return rows


def write_timeline_csv(rows, output_path: str):
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


if __name__ == "__main__":
    events, quarantined = collect_events("original/evidence")
    rows = build_report_rows(events)
    count = write_timeline_csv(rows, "timeline.csv")
    print(f"wrote {count} rows to timeline.csv")
    print(f"quarantined: {quarantined}")
