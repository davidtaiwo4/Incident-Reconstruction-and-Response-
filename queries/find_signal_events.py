"""Query: surfaces every non-noise ('signal') sysmon event across the full
evidence set, grouped by host. Signal events are identified structurally —
by event_id not matching the noise-NNNNNNN naming convention seen in the
bulk of the file — not by assuming any particular host, time, or content.
This is how to check whether the incident chain spans more than one host.
"""
import json
from collections import defaultdict


def find_signal_events(path):
    hits = defaultdict(list)
    with open(path) as f:
        for line_number, line in enumerate(f, start=1):
            rec = json.loads(line)
            event_id = rec.get("event_id", "")
            if not event_id.startswith("noise-"):
                hits[rec.get("computer")].append((line_number, rec))
    return hits


if __name__ == "__main__":
    hits = find_signal_events("original/evidence/host/sysmon.jsonl")
    print(f"distinct hosts with signal events: {len(hits)}")
    print()
    for computer, events in hits.items():
        print(f"--- {computer} ({len(events)} signal events) ---")
        for line_number, rec in events:
            print(f"  line {line_number}: {rec.get('event_type'):22s} "
                  f"{rec.get('image')} <- {rec.get('parent_image')}  "
                  f"({rec.get('detail')})  binding={rec.get('evidence_binding')}")
        print()
