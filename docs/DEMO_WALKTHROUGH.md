# Drastha SIH demo walkthrough

## What the demonstration proves

Drastha receives passive, one-way network metadata, identifies two separate
behaviours, and joins them into one explainable critical incident. It never
decrypts payloads and never sends traffic back toward the monitored network.

The demo uses versioned Zeek-style JSON fixtures so it is repeatable without
internet, Docker, a live attack, or access to protected infrastructure. The
parsing, detection, correlation, persistence, API, and analyst interactions are
real application code. Only the traffic itself is a controlled synthetic capture.

## Before entering the room

1. Connect the laptop to power and disable sleep.
2. Run `drastha demo-rehearse --evaluation-iterations 50`.
3. Confirm the report says `ready: true`.
4. Run `scripts/start-demo.ps1`, or run `drastha demo-serve --fresh`.
5. Confirm `http://127.0.0.1:8000` shows Sensor Online, SQLite and No Return Path.
6. Keep the PowerShell window open.

Docker is optional. Do not spend presentation time starting Docker if the local
SQLite mode is healthy.

## Two-minute primary script

### 0:00–0:20 — problem and safety

“Critical networks may allow us to observe traffic but prohibit any return
communication. Drastha therefore works entirely from passive metadata. It does
not scan, block, decrypt, or contact the protected network.”

Point to **Sensor Online**, **SQLite**, and **No Return Path**.

### 0:20–0:50 — run the real pipeline

Click **Replay attack**.

Explain the four real stages:

1. Parse passive connection and TLS metadata.
2. Detect periodic C2-like callbacks from timing consistency.
3. Detect unusual outbound volume relative to the source baseline.
4. Correlate both independent alerts into one critical incident.

Point to the healthy telemetry state and measured replay time. Describe that
number as detector/correlation demo time, not end-to-end production latency.

### 0:50–1:30 — investigate evidence

Click **Investigate top incident**. Show:

- the source and destination path;
- the attack timeline;
- observed values beside thresholds;
- separate confidence and policy risk score;
- detector limitations.

Say: “The analyst can see why the alert fired. A fingerprint or unusual domain
alone is never presented as proof of compromise.”

### 1:30–2:00 — human decision and portability

Change the status to **Investigating**, add a short note, and choose **Malicious**.
Then click **Export evidence**.

Close with: “Drastha turns isolated signals into a reviewable attack story while
preserving one-way network safety and human control.”

## Five-minute expanded script

Use the two-minute flow, then add:

- Search and severity filtering in the incident queue.
- The difference between severity, confidence, and risk score.
- DNS DGA model training: one model for the applicable DNS classification task;
  behavioural detectors are not separate ML models per attack.
- Per-threat evaluation results from `output/drastha_evaluation_report.json`.
- Telemetry degradation: malformed records are quarantined, timestamp skew is
  reported, and unusable streams block the scenario visibly.
- SQLite is the dependable offline demo path; PostgreSQL/Docker is an optional
  deployment path already supported.

## Recovery plan

### Browser is blank

Refresh once. If it remains blank, verify the PowerShell server window is still
open and revisit `http://127.0.0.1:8000`.

### Port 8000 is already in use

Run `drastha demo-serve --fresh --port 8001` and open
`http://127.0.0.1:8001`.

### Docker is unavailable

Continue with SQLite. Docker is not required for any primary demo feature.

### Zeek or WSL is unavailable

Use the bundled Zeek-style fixtures. Live PCAP conversion is not required for
the controlled demonstration.

### Incident does not appear

Click **Replay attack**, then refresh the queue. If the telemetry badge reports
unavailable or unusable, rerun `drastha demo-preflight` to identify the missing
fixture or frontend asset.

### Main UI cannot be recovered

Open `output/drastha_demo_rehearsal.json` and explain the recorded stage results,
then show `output/drastha_evaluation_report.json`. These are evidence backups,
not substitutes for unmeasured claims.

## Statements to avoid

- Do not claim production accuracy from the synthetic fixtures.
- Do not claim the detector timing is full PCAP-to-dashboard latency.
- Do not say Drastha decrypts TLS, detects every attack, or automatically blocks traffic.
- Do not say every attack needs its own ML model.
- Do not describe Docker, internet, or cloud access as mandatory for the demo.
