"""Analyst annotations layered onto the auto-generated timeline, keyed by
exact_locator. Confirmed by Aan for submission; defended live if selected.
"""
ANNOTATIONS = {
    "sysmon.jsonl:50001": {
        "attack_technique": "T1204.002",  # User Execution: Malicious File
        "primary_or_supporting": "primary",
        "confidence": "high",
        "alternative_interpretation": "None identified — direct evidence of attachment execution",
    },
    "sysmon.jsonl:50002": {
        "attack_technique": "T1059.001",  # Command and Scripting Interpreter: PowerShell
        "primary_or_supporting": "primary",
        "confidence": "high",
        "alternative_interpretation": "",
    },
    "sysmon.jsonl:50003": {
        "attack_technique": "T1053.005",  # Scheduled Task/Job: Scheduled Task
        "primary_or_supporting": "primary",
        "confidence": "high",
        "alternative_interpretation": "Could be a legitimate scheduled sync task — weakened by surrounding chain and by 'Northstar Support Sync' mimicking a benign IT naming convention",
    },
    "sysmon.jsonl:50004": {
        "attack_technique": "T1560.001",  # Archive Collected Data: Archive via Utility (tar.exe)
        "primary_or_supporting": "primary",
        "confidence": "high",
        "alternative_interpretation": "",
    },
    "sysmon.jsonl:50005": {
        "attack_technique": "T1071.001",  # Application Layer Protocol: Web Protocols (C2 channel establishment)
        "primary_or_supporting": "primary",
        "confidence": "high",
        "alternative_interpretation": "",
    },
    "sysmon.jsonl:50006": {
        "attack_technique": "T1070.004",  # Indicator Removal: File Deletion
        "primary_or_supporting": "primary",
        "confidence": "high",
        "alternative_interpretation": "",
    },
    "http.log:9": {
        "attack_technique": "T1041",  # Exfiltration Over C2 Channel — corrected from T1567
        "primary_or_supporting": "primary",
        "confidence": "high",
        "alternative_interpretation": "",
    },
    "files.log:9": {
        "attack_technique": "T1041",
        "primary_or_supporting": "supporting",
        "confidence": "high",
        "alternative_interpretation": "",
        "notes_override": "Same real-world transfer as http.log:9, observed independently via Zeek's file-analysis framework; see recovered/recovery-report.json for hash/count.",
    },
    "powershell-operational.jsonl:1": {
        "attack_technique": "T1059.001",
        "primary_or_supporting": "supporting",
        "confidence": "high",
        "alternative_interpretation": "",
    },
    "initial-access.eml": {
        "attack_technique": "T1566.001",  # Spearphishing Attachment
        "primary_or_supporting": "primary",
        "confidence": "medium",  # no Date/Message-ID header limits confidence in exact delivery timing
        "alternative_interpretation": "",
    },
    "conn.log:9": {
        "attack_technique": "T1071.001",
        "primary_or_supporting": "supporting",
        "confidence": "high",
        "alternative_interpretation": "",
    },
    "files.log:10": {
        "attack_technique": "",
        "primary_or_supporting": "supporting",
        "confidence": "high",
        "alternative_interpretation": "",
        "notes_override": "Confirmed HTTP response body ('accepted'), not a second exfiltration fragment — see decision-log D-006.",
    },
}
