import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "timeline-builder"))
from parsers.zeek import read_zeek_tsv, parse_file

FAKE_CONN_LOG = """#separator \\x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\tconn
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice
#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring
1900000000.000000\tTESTUID001\t10.0.0.9\t12345\t198.51.100.9\t443\ttcp\thttp
#close\t2099-01-01-00-00-00
"""


def test_conn_event_has_correlation_id_and_iso_timestamp(tmp_path):
    log_path = tmp_path / "conn.log"
    log_path.write_text(FAKE_CONN_LOG)

    events = list(parse_file(str(log_path), log_type="conn"))
    assert len(events) == 1
    event, status = events[0]
    assert status == "ok"
    assert event.event_type == "network_connection"
    assert event.correlation_id == "TESTUID001"

    from datetime import datetime, timezone
    expected = datetime.fromtimestamp(1900000000.0, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    assert event.normalized_timestamp_utc == expected
    assert event.host == "10.0.0.9"

def test_unset_and_empty_fields_are_distinguished(tmp_path):
    fake_log = FAKE_CONN_LOG.replace(
        "1900000000.000000\tTESTUID001\t10.0.0.9\t12345\t198.51.100.9\t443\ttcp\thttp",
        "1900000000.000000\tTESTUID002\t10.0.0.9\t12345\t198.51.100.9\t443\ttcp\t-",
    )
    log_path = tmp_path / "conn.log"
    log_path.write_text(fake_log)

    events = list(parse_file(str(log_path), log_type="conn"))
    event, status = events[0]
    assert event.extra["service"] is None  # "-" means unset, not empty string
