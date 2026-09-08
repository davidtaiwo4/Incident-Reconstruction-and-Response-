import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "timeline-builder"))
from parsers.email import parse_file

REAL_EML = "original/evidence/mail/initial-access.eml"


def test_parses_single_message_with_missing_headers():
    events = list(parse_file(REAL_EML))
    assert len(events) == 1
    event, status = events[0]
    assert status == "ok"
    assert event.event_type == "email_delivery"
    assert event.original_timestamp is None   # real message has no Date header
    assert event.extra["message_id"] is None  # real message has no Message-ID


def test_attachment_is_hashed_and_sized():
    event, status = list(parse_file(REAL_EML))[0]
    attachments = event.extra["attachments"]
    assert len(attachments) == 1
    attachment = attachments[0]
    assert attachment["size"] > 0
    assert len(attachment["sha256"]) == 64
