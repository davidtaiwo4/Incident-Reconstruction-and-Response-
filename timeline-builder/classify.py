"""Pure, source-agnostic classification and validation helpers.

These implement the contract exercised by public-tests.json.
Each source-specific parser (parsers/sysmon.py, parsers/zeek.py, ...) is
responsible for adapting a raw log line into the minimal shape these
functions expect before calling them.
"""
import json
from datetime import datetime, timedelta

SYSMON_EVENT_TYPE_MAP = {
    1: "process_start",
    # extend only as real numeric Sysmon event IDs turn up in the data
}

EVTX_EVENT_TYPE_MAP = {
    4624: "authentication",
    # extend only as real Windows event IDs turn up in the data
}


def classify_event(record: dict) -> dict:
    """Route a minimal record to the right source-specific classifier."""
    source = record.get("source")
    if source == "sysmon":
        return _classify_sysmon(record)
    if source == "evtx":
        return _classify_evtx(record)
    if source == "zeek_conn":
        return _classify_zeek_conn(record)
    if source == "zeek_dns":
        return _classify_zeek_dns(record)
    if source == "eml":
        return _classify_email(record)
    raise ValueError(f"no classifier registered for source: {source!r}")


def _classify_sysmon(record: dict) -> dict:
    # Real evidence may already carry event_type directly — pass it through.
    if "event_type" in record:
        return {"event_type": record["event_type"], "source_locator_required": True}
    event_id = record.get("event_id")
    return {"event_type": SYSMON_EVENT_TYPE_MAP.get(event_id, "unknown"),
            "source_locator_required": True}


def _classify_evtx(record: dict) -> dict:
    event_id = record.get("event_id")
    return {"event_type": EVTX_EVENT_TYPE_MAP.get(event_id, "unknown"),
            "source_locator_required": True}


def _classify_zeek_conn(record: dict) -> dict:
    return {"event_type": "network_connection", "correlation_id": record.get("uid")}


def _classify_zeek_dns(record: dict) -> dict:
    return {"event_type": "dns_query", "correlation_id": record.get("uid")}


def _classify_email(record: dict) -> dict:
    return {"event_type": "email_delivery"}


def normalize_clock(raw_timestamp: str, offset_seconds: int) -> dict:
    """Apply an explicit, documented clock offset. Never silently guess one."""
    dt = datetime.fromisoformat(raw_timestamp.replace("Z", "+00:00"))
    corrected = dt + timedelta(seconds=offset_seconds)
    return {"normalized": corrected.isoformat().replace("+00:00", "Z")}


def dedupe_ids(ids: list) -> dict:
    seen = set()
    output = []
    duplicate_count = 0
    for i in ids:
        if i in seen:
            duplicate_count += 1
            continue
        seen.add(i)
        output.append(i)
    return {"output_count": len(output), "duplicate_count": duplicate_count}


def order_split_archive(fragments: list) -> dict:
    ordered_streams = sorted({f["stream"] for f in fragments})
    return {"ordered_streams": ordered_streams}


def classify_change(record: dict) -> dict:
    if record.get("approved") is True:
        return {"classification": "benign_approved"}
    return {"classification": "needs_review"}


def parse_json_line(raw_line: str) -> dict:
    """Parse one JSONL line; never let a bad row crash the pipeline."""
    try:
        return {"record": json.loads(raw_line), "verdict": "ok"}
    except (json.JSONDecodeError, TypeError):
        return {"record": None, "verdict": "quarantine", "reason": "parse_error"}


def check_manifest_hash(expected_sha256: str, actual_sha256: str) -> dict:
    if expected_sha256 != actual_sha256:
        return {"verdict": "tampered", "ingest": False}
    return {"verdict": "verified", "ingest": True}


def validate_output_event(event: dict) -> dict:
    if not event.get("source_locator"):
        return {"verdict": "invalid_output"}
    return {"verdict": "ok"}
