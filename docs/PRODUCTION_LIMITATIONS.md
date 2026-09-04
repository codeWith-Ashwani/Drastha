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
- Sprint 14 adds 60-second synthetic conn-load/SQLite/ASGI timing and resource
  measurements. Signed 100 records/sec passed; signed 1,000 records/sec failed
  delivery/latency gates. See `SPRINT_14.md`. Real Zeek is unavailable on the
  tested machine. Live packet loss, all-protocol capacity, TLS/browser latency,
  multi-client contention and longer operational soaks remain unverified.
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
- Sprint 15 adds verified create-only analyst SQLite backup/restore, a protected
  loopback launcher, a real local HTTPS recovery drill and operations runbooks.
  High availability, remote deployment/service supervision, coordinated stream
  journal recovery, offsite encrypted backup, upgrade/migration and power-loss
  testing remain open. Readiness never auto-certifies the installation.

## Integrations and governance

- Add controlled SIEM/SOAR export on the monitoring side of the diode.
- Define environment-specific allowlists, escalation policies and ownership.
- Review privacy, evidence-handling and sector-specific compliance requirements.
- Establish model/detector version approval and rollback procedures.

These limitations should be presented honestly. They do not prevent the current
prototype from demonstrating passive ingestion, explainable detection,
cross-detector correlation, persistence, analyst review and offline operation.
