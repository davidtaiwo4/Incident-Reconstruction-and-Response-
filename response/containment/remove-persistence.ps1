<#
Removes the confirmed malicious scheduled task ("Northstar Support Sync",
created by schtasks.exe as a child of powershell.exe — sysmon.jsonl line
50003, host NS-WKS-101). Safe by design: dry run by default; requires
-Confirm to actually remove anything.
#>
param(
    [switch]$Confirm
)

$TaskName = "Northstar Support Sync"

Write-Host "Containment target: scheduled task '$TaskName' on this host."

if (-not $Confirm) {
    Write-Host "Dry run only. Would run:"
    Write-Host "  Unregister-ScheduledTask -TaskName '$TaskName' -Confirm:`$false"
    Write-Host "Re-run with -Confirm to actually remove the task."
    exit 0
}

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
Write-Host "Removed scheduled task: $TaskName"
