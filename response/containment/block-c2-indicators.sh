#!/usr/bin/env bash
# Containment: blocks the confirmed C2 destination observed in incident.pcap
# (conn.log: 10.71.40.161 -> 203.0.113.195:8443, http.log Host header:
# sync-v1.updates-example.invalid). Safe by design: defaults to printing
# the exact commands (dry run); requires --apply to actually change firewall state.
set -euo pipefail

C2_IP="203.0.113.195"
C2_PORT="8443"
C2_DOMAIN="sync-v1.updates-example.invalid"

APPLY=false
if [[ "${1:-}" == "--apply" ]]; then
  APPLY=true
fi

CMDS=(
  "nft add rule inet filter output ip daddr ${C2_IP} tcp dport ${C2_PORT} drop"
  "echo '0.0.0.0 ${C2_DOMAIN}' | tee -a /etc/hosts"
)

echo "Containment plan for confirmed C2 indicator (${C2_DOMAIN} / ${C2_IP}:${C2_PORT}):"
for cmd in "${CMDS[@]}"; do
  echo "  ${cmd}"
done

if [[ "${APPLY}" == true ]]; then
  echo
  echo "Applying (requires root / matching nft table):"
  for cmd in "${CMDS[@]}"; do
    eval "${cmd}"
  done
else
  echo
  echo "Dry run only — rerun with --apply to execute."
fi
