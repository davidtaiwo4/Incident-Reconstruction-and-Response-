# Continuity Record — Stage 9

## 1. Previous-stage commit and exact component reused

Stage 9's assigned input is a separately sealed, hash-verified archive
(`soc-analysis-stage-9-shared-b1.tar.gz`, evidence marker `UBI-A9-4D6D187D6728`,
private assignment set D5) — not a direct data handoff from Stage 8.

*What genuinely carries forward is design pattern, not data:*

**From Stage 5 (Hunt Engine) via Stage 8's own adoption of it**
Component reused: the COALESCE-style, version-aware field normalization
pattern (branch explicitly per schema version rather than assume one fixed
shape). Stage 9's `timeline-builder/parsers/sysmon.py` applies the same
principle: real evidence carries three distinct `schema_version` values
(1/2/3) even though all three share one observed key set in this pack's
noise floor, and the parser does not assume that will remain true under a
hidden fixture.
Stage 5 commit: `30036cc9ab3a7e580d6a5c80f0605f7d192f5bbb`

**From Stage 6 (Honeypot Pipeline) via Stage 7 and Stage 8's adoption of it**
Component reused: deriving a stable identifier from a structurally reliable
source rather than trusting a fixture-supplied label. Stage 9 extends this
directly: Zeek's own `uid` field is *not* structurally reliable (it is
regenerated randomly on every Zeek invocation — confirmed empirically
mid-build when a re-run of Zeek produced a different `uid` for the same
underlying connection). All Stage 9 correlation logic re-derives `uid` from
whatever `conn.log`/`files.log` currently exists at run time rather than
ever hardcoding one; cross-source correlation instead relies on the
`evidence_binding` token embedded in event content, which is stable across
reruns because it originates from the evidence itself, not from Zeek's
session bookkeeping.
Stage 6 commit: `d1113b96ec56512e7d2e42ce890b1279b0bc4f5f`

**From Stage 8 (Detection Engineering)**
Component reused: the discipline of separating a normalized detection input
from validation/ground-truth data, and of writing both a positive and a
negative fixture for every rule rather than only proving a rule fires.
Stage 9's `detections/detection-rules/tests/` follows this for both the
Sigma rule (positive: real 3-step Office/PowerShell chain; negative: benign
explorer-spawned PowerShell) and the Zeek C2 rule (positive: the real sealed
`incident.pcap`; negative: a self-constructed synthetic benign-HTTP pcap,
since the evidence pack did not supply a benign-traffic comparison capture).

## 2. Interface consumed and backward-compatible extension

No Stage 5-8 evidence-record schema is consumed at runtime this stage.
Stage 9 defines its own `NormalizedEvent` schema
(`timeline-builder/schema.py`) — `source, raw_locator, event_type,
original_timestamp, normalized_timestamp_utc, host, identity,
correlation_id, parser_status, parser_note, extra` — built to satisfy this
stage's own public-fixture contract (`public-tests.json`), not a carried-
forward prior-stage schema, since this stage's brief and evidence shape
(JSONL host logs, an `.eml`, a real `.pcap`) differ materially from prior
stages' inputs.

The schema is extended, not replaced, as new sources were added: sysmon,
powershell, eml, and zeek (conn/http/files/dns) parsers all emit the same
`NormalizedEvent` shape, so `timeline-builder/build_timeline.py` assembles
all four sources through one unchanged interface. Adding a fifth source
would require no change to the schema or the assembly logic — only a new
parser module.

## 3. Evidence that prior raw-to-result provenance remains intact

This stage did not read, copy, or modify any Stage 5-8 raw artifact,
archive, or repository. Stage 9 operates entirely on its own independently
assigned archive (`soc-analysis-stage-9-shared-b1.tar.gz`, SHA-256
`df8fb093a6a69ca885a0f22518f842cf6a470232a6df821fb759a507389f2022`) plus its
own public fixtures (`public-tests.json`) and self-constructed synthetic
test fixtures (parser unit tests, `detections/detection-rules/tests/fixtures/`).
Provenance intact by construction: no shared file paths, no shared database,
no in-place edits to any prior-stage output.

## 4. Migration record for every incompatible change

No prior-stage schema, field, or component was renamed, removed, or reused
incorrectly this stage — there was nothing to migrate, since Stage 9's
evidence shape (host JSONL + email + real pcap) required a purpose-built
schema rather than adapting a prior one. This mirrors Stage 8's own D-record
finding that the track's stated "detection engineering consumes the
verified behaviours" progression does not always match what a given stage's
actual sealed input requires; Stage 9 assigns its own sealed input the same
way Stage 8 did.

## 5. Component, schema, evidence, and decision record handed to the next stage

- **Timeline pipeline:** `timeline-builder/schema.py` (NormalizedEvent),
  `timeline-builder/classify.py` (source-agnostic classification/validation
  helpers, tested against all 12 `public-tests.json` fixtures),
  `timeline-builder/parsers/` (sysmon, powershell, email, zeek — four
  evidence types, satisfying the brief's minimum), `timeline-builder/build_timeline.py`
  (single entry point, deterministic sort, explicit clock-offset hook).
- **Confirmed clock-correction methodology:** `scripts/find_clock_offsets.py`
  — a reusable, generic two-technique approach (shared-identifier
  correlation + per-source time-range comparison) that is not specific to
  this case's tokens or hosts and can be reapplied to any future
  multi-source dataset.
- **Recovered archive pipeline:** `recovered/recover.py` — single entry
  point from raw pcap to hashed, counted, extracted archive; cross-validated
  by an independent raw-TCP reconstruction method
  (`scripts/extract_raw_tcp_payload.py`) and a generic inspection tool
  (`scripts/inspect_recovered_candidate.py`).
- **Verified detections:** one Sigma rule (Office-to-archive-exfil process
  chain) and one Zeek notice rule (confirmed C2 domain), each with a real
  positive case from this incident's own evidence and a constructed negative
  case, all under `detections/detection-rules/`.
- **Response content:** `detections/response/containment/` (network block +
  scheduled-task removal, both dry-run-by-default) and
  `detections/response/recovery/restore-host-checklist.md`, scoped
  explicitly to the confirmed single-host impact boundary.
- **Named, unresolved blind spots handed forward:** Zeek's `uid`
  non-determinism across reruns (documented in `assessment-manifest.json`
  known_limitations — affects `timeline.csv` byte-stability, not its
  correctness); no real `.evtx` evidence existed in this pack, so
  `PARSER-EVTX` is verified only against the public fixture; the
  PowerShell containment script is verified via static checks only (no
  Windows/pwsh runtime available in this environment); the Zeek C2 rule's
  negative test relies on a self-constructed synthetic pcap rather than a
  supplied benign-traffic capture.
- **Decision record:** `decision-log.md` in full, covering the acquisition-
  verification scope decision (D-001), the CORE_FIELDS schema correction
  (D-002), the clock-offset derivation and its three-pair corroboration
  (D-003), the confirmed single-host impact boundary (D-004), the
  cross-validated archive recovery (D-005), the response-body
  misidentification resolved (D-006), the dry-run-by-default containment
  design (D-007), the detections/response directory placement (D-008), and the recovery automation decision (D-009)
  — handed forward so a later reviewer does not assume manual steps or
  unexamined assumptions where none exist.
