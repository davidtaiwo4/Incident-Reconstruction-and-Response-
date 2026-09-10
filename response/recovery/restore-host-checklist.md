# Recovery checklist — NS-WKS-101

Scope: this is the only host confirmed affected (see queries/find_signal_events.py —
zero signal events found on any other host in the sysmon evidence).

1. Preserve evidence before remediation
   - Confirm this host is isolated from the network (containment step) before touching it.
   - Do not delete or overwrite any artifact referenced in evidence-index.csv.

2. Remove confirmed persistence
   - Run `containment/remove-persistence.ps1 -Confirm` on the affected host.
   - Verify removal: `Get-ScheduledTask -TaskName "Northstar Support Sync"` should return nothing.

3. Re-image or restore from known-good backup
   - Given a scheduled task and a delivered/executed Office macro were confirmed,
     re-imaging the host from a known-good backup is preferred over manual cleanup —
     manual removal cannot fully rule out additional undiscovered persistence.

4. Rotate credentials for the affected identity
   - Identity confirmed on this host: northstar\analyst1 (sysmon.jsonl lines 50001-50006).
   - No credential theft was directly observed in the available evidence — this step
     is precautionary, not evidence-driven, and should be labeled as such in the report.

5. Verify containment held
   - Confirm the blocked C2 indicator (sync-v1.updates-example.invalid / 203.0.113.195:8443)
     shows no further outbound attempts in subsequent monitoring.

## What this recovery plan does NOT claim
- It does not claim other hosts were affected (none were found).
- It does not claim credential compromise occurred (not evidenced).
- Live execution against a real Windows host was not performed in this environment;
  remove-persistence.ps1 is verified via static content checks only (see
  containment/tests/test_containment_scripts.py).
