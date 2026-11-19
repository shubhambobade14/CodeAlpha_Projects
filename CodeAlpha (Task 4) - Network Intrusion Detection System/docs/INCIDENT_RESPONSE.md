# Alert triage and response playbook

1. **Receive**: record alert time, SID, source, destination, protocol and sensor interface.
2. **Validate**: check rule context, frequency, expected lab activity and corroborating logs; treat alerts as leads, not proof.
3. **Classify**: decide false positive, benign true positive, or suspicious event; record confidence and business impact.
4. **Contain (approval required)**: for confirmed threats, notify the responsible owner and follow the organization's change/incident policy. Isolation or firewall changes require authorization and rollback plans. This project does not block traffic automatically.
5. **Investigate**: preserve relevant sanitized logs, verify host health, determine scope, document timeline.
6. **Recover**: restore normal operations using approved processes; review detection rules and false positives.
7. **Close**: record disposition, actions, evidence and lessons learned.

## Incident record template
| Field | Value |
|---|---|
| Incident ID | |
| Timestamp (UTC) | |
| Signature / SID | |
| Source / Destination | |
| Evidence and corroboration | |
| Severity / confidence | |
| Owner / authorization | |
| Action and rollback | |
| Resolution | |

Never publish real IPs, payloads, credentials, or customer data in a public repository.
