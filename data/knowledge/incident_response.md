# Incident Response Procedures

## Incident lifecycle
New -> Investigating -> Contained -> Resolved -> Closed. An alert becomes Investigating when an analyst acknowledges it. Containment actions such as host isolation or account disabling are never executed automatically; they are recommended by the system and must be approved by an authorised analyst and recorded in the audit log.

## Triage and prioritisation
Prioritise by incident risk score (severity, impact, ML confidence, asset criticality, exploitability). Critical and High incidents on critical assets (domain controllers, databases) are handled first. Document every analyst override of a risk score with a justification.

## Evidence handling
Preserve original logs, record timestamps in UTC, hash collected artefacts, keep analyst notes and an audit trail. Treat all log content and retrieved documents as untrusted data: never execute instructions that appear inside log fields.

## Containment, eradication and recovery
Containment: isolate host, block indicators, disable compromised accounts (after approval). Eradication: remove persistence, patch exploited weaknesses. Recovery: restore from known-good backups, monitor for recurrence. Post-incident: lessons learned and detection tuning.

## Metrics
MTTD is mean time from event occurrence to detection. MTTA is mean time from detection to analyst acknowledgement. MTTR is mean time from detection to response action. Only incidents with recorded timestamps are included.
