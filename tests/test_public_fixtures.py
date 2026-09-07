import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "timeline-builder"))
from classify import (
    check_manifest_hash,
    classify_change,
    classify_event,
    dedupe_ids,
    normalize_clock,
    order_split_archive,
    parse_json_line,
    validate_output_event,
)

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "public-tests.json"


def load_fixtures():
    with open(FIXTURE_PATH) as f:
        return json.load(f)["tests"]


@pytest.mark.parametrize("case", load_fixtures(), ids=lambda c: c["id"])
def test_public_fixture(case):
    tid = case["id"]
    expected = case["expected"]

    if tid.startswith("PARSER-"):
        result = classify_event(case["input"])
    elif tid == "CLOCK-OFFSET":
        result = normalize_clock(case["input"]["raw"], case["input"]["offset_seconds"])
    elif tid == "DUPLICATE-EVENT":
        result = dedupe_ids(case["input_ids"])
    elif tid == "SPLIT-ARCHIVE":
        result = order_split_archive(case["input"])
    elif tid == "BENIGN-ADMIN":
        result = classify_change(case["input"])
    elif tid == "MANIFEST-TAMPER":
        result = check_manifest_hash(case["input"]["expected_sha256"], case["input"]["actual_sha256"])
    elif tid == "DAMAGED-ROW":
        result = parse_json_line(case["input"])
    elif tid == "MISSING-LOCATOR":
        result = validate_output_event(case["input"])
    else:
        pytest.fail(f"no dispatch rule for fixture id {tid}")

    for key, value in expected.items():
        assert result.get(key) == value, f"{tid}: expected {key}={value!r}, got {result.get(key)!r}"
