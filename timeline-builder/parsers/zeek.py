"""Parser for Zeek TSV logs (conn.log, http.log, files.log, dns.log).

Zeek's own conventions are respected rather than collapsed:
  "-"       -> None (field genuinely unset)
  "(empty)" -> ""   (field present but empty)
Anything not mapped to a named NormalizedEvent field is preserved in extra.
"""
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from schema import NormalizedEvent


def _field(value):
    if value == "-":
        return None
    if value == "(empty)":
        return ""
    return value


def _epoch_to_iso(ts_str):
    try:
        return datetime.fromtimestamp(float(ts_str), tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError):
        return None


def read_zeek_tsv(path: str):
    """Yields (line_number, row_dict) for each data row, skipping comment lines."""
    fields = None
    with open(path) as f:
        for line_number, raw_line in enumerate(f, start=1):
            line = raw_line.rstrip("\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#") or not line:
                continue
            if fields is None:
                raise ValueError(f"{path}:{line_number}: data row before #fields header")
            values = line.split("\t")
            row = {k: _field(v) for k, v in zip(fields, values)}
            yield line_number, row


def _conn_row_to_event(row, line_number, source_filename):
    return NormalizedEvent(
        source="zeek_conn",
        raw_locator=f"{source_filename}:{line_number}",
        event_type="network_connection",
        original_timestamp=row.get("ts"),
        normalized_timestamp_utc=_epoch_to_iso(row.get("ts")),
        host=row.get("id.orig_h"),
        identity=None,
        correlation_id=row.get("uid"),
        parser_status="ok",
        extra={k: v for k, v in row.items() if k not in {"ts", "uid"}},
    )


def _http_row_to_event(row, line_number, source_filename):
    return NormalizedEvent(
        source="zeek_http",
        raw_locator=f"{source_filename}:{line_number}",
        event_type="http_request",
        original_timestamp=row.get("ts"),
        normalized_timestamp_utc=_epoch_to_iso(row.get("ts")),
        host=row.get("id.orig_h"),
        identity=None,
        correlation_id=row.get("uid"),
        parser_status="ok",
        extra={k: v for k, v in row.items() if k not in {"ts", "uid"}},
    )


def _files_row_to_event(row, line_number, source_filename):
    return NormalizedEvent(
        source="zeek_files",
        raw_locator=f"{source_filename}:{line_number}",
        event_type="file_transfer",
        original_timestamp=row.get("ts"),
        normalized_timestamp_utc=_epoch_to_iso(row.get("ts")),
        host=row.get("id.orig_h"),
        identity=None,
        correlation_id=row.get("uid"),
        parser_status="ok",
        extra={k: v for k, v in row.items() if k not in {"ts", "uid"}},
    )


def _dns_row_to_event(row, line_number, source_filename):
    return NormalizedEvent(
        source="zeek_dns",
        raw_locator=f"{source_filename}:{line_number}",
        event_type="dns_query",
        original_timestamp=row.get("ts"),
        normalized_timestamp_utc=_epoch_to_iso(row.get("ts")),
        host=row.get("id.orig_h"),
        identity=None,
        correlation_id=row.get("uid"),
        parser_status="ok",
        extra={k: v for k, v in row.items() if k not in {"ts", "uid"}},
    )


_CONVERTERS = {
    "conn": _conn_row_to_event,
    "http": _http_row_to_event,
    "files": _files_row_to_event,
    "dns": _dns_row_to_event,
}


def parse_file(path: str, log_type: str = None):
    """Yields (NormalizedEvent, status) for every data row in a Zeek TSV log."""
    filename = Path(path).name
    if log_type is None:
        log_type = filename.split(".")[0]  # "conn.log" -> "conn"
    converter = _CONVERTERS.get(log_type)
    if converter is None:
        raise ValueError(f"no converter registered for zeek log type: {log_type!r}")

    for line_number, row in read_zeek_tsv(path):
        yield converter(row, line_number, source_filename=filename), "ok"
