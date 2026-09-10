"""Static + dry-run tests for containment scripts.

The PowerShell script can't be executed here (no Windows/pwsh runtime in
this Linux environment) — that's a documented limitation, verified via
static content checks instead. The bash script CAN be syntax-checked and
dry-run executed for real, so we do both.
"""
import subprocess
from pathlib import Path

CONTAINMENT_DIR = Path(__file__).resolve().parent.parent
BASH_SCRIPT = CONTAINMENT_DIR / "block-c2-indicators.sh"
PS_SCRIPT = CONTAINMENT_DIR / "remove-persistence.ps1"


def test_bash_script_has_valid_syntax():
    result = subprocess.run(["bash", "-n", str(BASH_SCRIPT)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_bash_script_targets_confirmed_indicators():
    content = BASH_SCRIPT.read_text()
    assert "203.0.113.195" in content
    assert "sync-v1.updates-example.invalid" in content
    assert "8443" in content
    assert "APPLY=false" in content


def test_bash_script_dry_run_does_not_modify_system():
    result = subprocess.run(["bash", str(BASH_SCRIPT)], capture_output=True, text=True)
    assert result.returncode == 0
    assert "Dry run only" in result.stdout
    assert "nft add rule" in result.stdout  # printed, never executed


def test_ps_script_targets_confirmed_task_name():
    content = PS_SCRIPT.read_text()
    assert "Northstar Support Sync" in content


def test_ps_script_defaults_to_dry_run():
    content = PS_SCRIPT.read_text()
    assert "-Confirm" in content
    assert "Dry run only" in content
