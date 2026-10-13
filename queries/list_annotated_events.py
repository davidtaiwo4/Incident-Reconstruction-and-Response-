"""Filters timeline.csv down to rows carrying an analyst annotation
(non-blank attack_technique) — for fast review, not a second deliverable
file. The full timeline.csv remains the single required source of truth;
this is just a lens onto it.
"""
import csv

with open("timeline.csv") as f:
    reader = csv.DictReader(f)
    rows = [r for r in reader if r["attack_technique"].strip()]

print(f"{len(rows)} annotated rows out of the full timeline\n")
for row in rows:
    print(f"{row['event_id']}  {row['utc_time']}  {row['attack_technique']:10s} "
          f"{row['primary_or_supporting']:10s} {row['activity'][:80]}")
