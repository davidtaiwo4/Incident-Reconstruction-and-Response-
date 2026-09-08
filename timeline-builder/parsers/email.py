"""Parser for the initial-access.eml evidence source.

Single-message .eml file (not a maildir/mbox), so raw_locator is the
filename itself. Message-ID and Date are treated as optional — their
absence is preserved as None, never guessed at or backfilled.
"""
import email
import hashlib
import sys
from email import policy
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from schema import NormalizedEvent


def parse_file(path: str):
    """Yields exactly one (NormalizedEvent, status) for the single message."""
    filename = Path(path).name

    with open(path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    attachments = []
    body_text = None
    for part in msg.walk():
        content_type = part.get_content_type()
        filename_part = part.get_filename()
        if filename_part:
            payload = part.get_payload(decode=True) or b""
            attachments.append({
                "filename": filename_part,
                "content_type": content_type,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            })
        elif content_type == "text/plain" and body_text is None:
            payload = part.get_payload(decode=True) or b""
            body_text = payload.decode(errors="replace")

    extra = {
        "from": msg["From"],
        "to": msg["To"],
        "subject": msg["Subject"],
        "message_id": msg["Message-ID"],  # None if absent — do not fabricate
        "body_text": body_text,
        "attachments": attachments,
    }

    event = NormalizedEvent(
        source="eml",
        raw_locator=filename,
        event_type="email_delivery",
        original_timestamp=msg["Date"],  # None if absent
        normalized_timestamp_utc=None,   # cannot normalize a clock we don't have
        host=None,
        identity=msg["To"],
        parser_status="ok",
        extra=extra,
    )
    yield event, "ok"
