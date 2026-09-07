"""Common normalized event schema for the Stage 9 super-timeline pipeline."""
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class NormalizedEvent:
    source: str
    raw_locator: str                      # e.g. "sysmon.jsonl:142"
    event_type: Optional[str] = None
    original_timestamp: Optional[str] = None
    normalized_timestamp_utc: Optional[str] = None
    host: Optional[str] = None
    identity: Optional[str] = None
    correlation_id: Optional[str] = None
    parser_status: str = "ok"             # ok | quarantined | tampered
    parser_note: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)
