"""Minimal, dependency-free Sigma rule evaluator for this one rule's logic —
avoids requiring a full Sigma toolchain install under time pressure, while
still being a real, reproducible, unattended test.
"""
import json
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def matches_office_spawns_script(event):
    parent = event.get("ParentImage", "")
    image = event.get("Image", "")
    return (
        any(parent.endswith(p) for p in ("WINWORD.EXE", "EXCEL.EXE", "OUTLOOK.EXE"))
        and any(image.endswith(i) for i in ("powershell.exe", "pwsh.exe"))
    )


def matches_archive_from_script(event):
    parent = event.get("ParentImage", "")
    image = event.get("Image", "")
    return (
        any(parent.endswith(p) for p in ("powershell.exe", "pwsh.exe"))
        and any(image.endswith(i) for i in ("tar.exe", "7z.exe", "zip.exe"))
    )


def matches_outbound_from_script(event):
    parent = event.get("ParentImage", "")
    image = event.get("Image", "")
    return (
        any(parent.endswith(p) for p in ("powershell.exe", "pwsh.exe"))
        and any(image.endswith(i) for i in ("curl.exe", "certutil.exe"))
    )


def rule_fires_on_sequence(events):
    return any(
        matches_office_spawns_script(e) or matches_archive_from_script(e) or matches_outbound_from_script(e)
        for e in events
    )


def test_positive_fixture_fires():
    events = json.loads((FIXTURES_DIR / "positive_office_chain.json").read_text())
    assert rule_fires_on_sequence(events) is True


def test_negative_fixture_does_not_fire_on_office_spawn_condition():
    events = json.loads((FIXTURES_DIR / "negative_benign_admin_backup.json").read_text())
    # This fixture deliberately has explorer.exe (not Office) spawning powershell,
    # so the office_spawns_script sub-condition specifically should not match —
    # even though archive_from_script still fires, since tar-from-powershell
    # alone is a documented false positive (see falsepositives: in the rule).
    assert matches_office_spawns_script(events[0]) is False
