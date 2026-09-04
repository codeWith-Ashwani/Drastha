# Drastha production-readiness backlog

The SIH offline demonstration is complete. The following items are intentionally
deferred because they are production requirements, not demo blockers.

## Data and model validation

- Acquire licensed, versioned real datasets for every claimed threat family.
- Calibrate thresholds for each deployment and measure false positives over time.
- Evaluate the DNS model with family-separated external holdouts and monitor drift.
- Add public-suffix-aware domain parsing and encrypted-DNS telemetry where available.

## Capture and scale

- Pin and harden the Zeek runtime used for continuous capture.
- Measure packet loss, sustained throughput, end-to-end latency, CPU, memory and disk.
- Sprint 12 adds bounded local-file backpressure and durable checkpoints/recovery.
  Seamless rotation, state compaction/retention, multi-sensor ordering and sustained
  overload capacity remain open; see `SPRINT_12.md` for explicit session budgets.
- Add service-aware UDP reflection/amplification attribution.

## Security and operations

- Sprint 13 adds opt-in HTTPS-only opaque-token/Basic roles for SQLite. SSO/MFA,
  session/revocation lifecycle, rate limiting and production identity operations
  remain open. Existing demo mode is still explicitly unprotected.
- Protect secrets, encrypt stored evidence and define retention/deletion policy.
- Sprint 13 adds HMAC audit/state verification and signed export receipts; external
  head anchoring, key custody/rotation, dependency scanning and signed releases
  remain open. Report-only retention is not complete evidence erasure.
- Complete a formal threat model, penetration test and incident-response procedure.
- Add high availability, database backup/restore and upgrade/migration testing.

## Integrations and governance

- Add controlled SIEM/SOAR export on the monitoring side of the diode.
- Define environment-specific allowlists, escalation policies and ownership.
- Review privacy, evidence-handling and sector-specific compliance requirements.
- Establish model/detector version approval and rollback procedures.

These limitations should be presented honestly. They do not prevent the current
prototype from demonstrating passive ingestion, explainable detection,
cross-detector correlation, persistence, analyst review and offline operation.
