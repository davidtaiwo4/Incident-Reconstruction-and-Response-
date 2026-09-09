"""Two techniques for spotting clock offsets across evidence sources:

1. Identifier correlation: extract identifier-shaped tokens from every
   event's extra fields, group events across sources that share a token,
   and print each group sorted by normalized time. A causally-linked group
   that looks out of order is a strong offset signal.

2. Per-source time range: print each source's min/max normalized timestamp.
   A source whose whole range is shifted by a suspiciously round number of
   seconds/hours relative to the others suggests a systematic offset.

Adjust TOKEN_RE if your data's identifiers aren't 16 lowercase hex chars.
"""
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "timeline-builder"))
from parsers import email as email_parser
from parsers import powershell as powershell_parser
from parsers import sysmon as sysmon_parser
from parsers import zeek as zeek_parser

TOKEN_RE = re.compile(r'\b[0-9a-f]{16}\b')


def load_all_events():
    events = []
    for event, status in sysmon_parser.parse_file("original/evidence/host/sysmon.jsonl"):
        if status == "ok":
            events.append(event)
    for event, status in powershell_parser.parse_file("original/evidence/host/powershell-operational.jsonl"):
        if status == "ok":
            events.append(event)
    for event, status in email_parser.parse_file("original/evidence/mail/initial-access.eml"):
        if status == "ok":
            events.append(event)
    for logname, logtype in [("conn.log", "conn"), ("http.log", "http"), ("files.log", "files")]:
        path = f"working/zeek-logs/{logname}"
        if Path(path).exists():
            for event, status in zeek_parser.parse_file(path, log_type=logtype):
                if status == "ok":
                    events.append(event)
    return events


def tokens_in_event(event):
    blob = " ".join(str(v) for v in event.extra.values())
    return set(TOKEN_RE.findall(blob))


def print_correlated_groups(events):
    groups = defaultdict(list)
    for event in events:
        for token in tokens_in_event(event):
            groups[token].append(event)

    for token, group in groups.items():
        if len({e.source for e in group}) < 2:
            continue  # only care about identifiers that link multiple sources
        print(f"=== shared identifier: {token} ({len(group)} events across {len({e.source for e in group})} sources) ===")
        for event in sorted(group, key=lambda e: e.normalized_timestamp_utc or ""):
            ts = event.normalized_timestamp_utc or "(no timestamp)"
            print(f"  {ts:30s} {event.source:10s} {event.event_type:22s} {event.raw_locator}")
        print()


def print_source_time_ranges(events):
    ranges = defaultdict(lambda: [None, None])
    for event in events:
        ts = event.normalized_timestamp_utc
        if not ts:
            continue
        lo, hi = ranges[event.source]
        if lo is None or ts < lo:
            ranges[event.source][0] = ts
        if hi is None or ts > hi:
            ranges[event.source][1] = ts

    print("=== per-source time range ===")
    for source, (lo, hi) in ranges.items():
        print(f"  {source:12s} {lo}  ->  {hi}")


if __name__ == "__main__":
    events = load_all_events()
    print_correlated_groups(events)
    print_source_time_ranges(events)
