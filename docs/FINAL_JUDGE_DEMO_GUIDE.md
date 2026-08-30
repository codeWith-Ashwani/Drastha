# Drastha final SIH judge demonstration guide

This is the presentation-day runbook. Follow it in order. The primary demo takes
about five minutes and works completely offline.

## 1. What story are we demonstrating?

An internal endpoint, `10.0.0.44`, first makes small, regular encrypted
connections to an external endpoint. This resembles a command-and-control
callback. Later, the same internal endpoint sends an unusually large amount of
data outward. Drastha detects the two behaviours independently and correlates
them into one critical incident.

The controlled traffic is stored as versioned Zeek-style fixtures. This makes
the demonstration safe and repeatable. The ingestion, validation, detection,
correlation, database, API, dashboard, analyst decision and export are real code.

## 2. Complete pipeline to explain

```text
Controlled attack traffic / PCAP
              |
              v
    Passive TAP or data diode
       one-way observation
              |
              v
       Zeek network metadata
     conn.log + TLS metadata
              |
              v
  Normalization and quality checks
 malformed records / loss / skew visible
              |
              v
   Behaviour and ML detection layer
 C2 timing | Exfil volume | DNS model | Recon | DDoS
              |
              v
     Cross-detector correlation
 same source + related time window
              |
              v
   Risk-prioritized incident store
       SQLite offline demo
              |
              v
        FastAPI analyst API
              |
              v
       Drastha dashboard
 timeline | evidence | feedback | export
```

### Explain every stage in simple language

1. **Attack traffic:** The fixture represents what Zeek observed during a
   controlled C2 and data-transfer scenario. We do not attack a real system in
   the judging room.
2. **One-way collection:** A TAP or data diode lets the monitoring side observe
   traffic but prevents Drastha from contacting the protected network.
3. **Zeek metadata:** Drastha uses connection timing, direction, sizes, states,
   DNS names and visible TLS metadata. It does not require payload decryption.
4. **Quality checks:** Missing files, malformed records and timestamp skew are
   reported. Excessively damaged telemetry blocks the result instead of silently
   presenting a misleading incident.
5. **Detection:** The C2 detector looks for repeated, stable callbacks. The
   exfiltration detector looks for outbound volume and direction that exceed the
   source baseline. Reconnaissance and DDoS are behavioural detectors. The DNS
   DGA use case has the trainable character n-gram model.
6. **Correlation:** Alerts from the same source and related time window are
   combined. Two independent detectors strengthen the attack story.
7. **Risk:** Threat weights, detector agreement and confidence create a
   transparent priority score. Risk is kept separate from model confidence.
8. **Dashboard:** The analyst sees why the incident fired, changes its status,
   records a human decision and exports the evidence.

## 3. Preparation before presentation day

On a fresh laptop, connect to the internet once and run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/setup-demo.ps1
```

This creates `.venv`, installs the API, builds the dashboard and rehearses the
entire demo twice.

After setup, verify that `output/drastha_demo_rehearsal.json` contains:

- `ready: true`
- `attack_story_completed: true`
- `critical_incident_created: true`
- `replay_is_idempotent: true`
- `evaluation_passed: true`

Then disconnect the internet and run one more rehearsal. This proves that the
primary demonstration is truly offline.

## 4. Starting the demo in the judging room

From the project folder, run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/start-demo.ps1
```

Keep the PowerShell window open. The browser opens
`http://127.0.0.1:8000` automatically.

Before speaking, confirm these indicators:

- **Sensor Online**
- **SQLite**
- **No Return Path**
- one critical incident in the queue

## 5. Five-minute presentation script

### 0:00–0:35 — introduce the problem

Point to **No Return Path** and say:

> “Critical networks may permit passive observation but prohibit any return
> communication. Drastha analyses one-way network metadata without scanning,
> decrypting or contacting the protected network.”

### 0:35–1:05 — introduce the controlled attack

Point to the attack-chain card and say:

> “Our controlled scenario has two stages. The internal device first makes
> regular encrypted callbacks, which can indicate command-and-control. The same
> device later sends an unusual volume of data outward. Individually these are
> alerts; together they form a stronger incident.”

### 1:05–1:40 — run attack-to-detection pipeline

Click **Replay attack**.

While it runs, say:

> “This button is not playing an animation or loading a final screenshot. It
> reparses the telemetry, runs the C2 and exfiltration detectors, correlates the
> alerts and persists the resulting incident.”

After completion, point to:

- `healthy` telemetry;
- **Detected from repeated timing**;
- **Detected from directional volume**;
- **Correlation complete**;
- the measured processing time.

Say that the displayed time measures the local detector/correlation demo path,
not full production PCAP-to-dashboard latency.

### 1:40–3:10 — investigate the incident

Click **Investigate top incident**.

Show the following in order:

1. **Risk 100:** a policy priority score produced by multiple threat categories,
   detector agreement and confidence.
2. **Detector confidence:** kept separate from severity and risk.
3. **Attack timeline:** periodic callback followed by outbound anomaly.
4. **C2 evidence:** connection count, mean interval, timing variation, transfer
   size variation and supporting TLS metadata.
5. **Exfiltration evidence:** outbound bytes, outbound-to-inbound ratio, source
   baseline comparison and destination context.
6. **Limitations:** visible beside the evidence so the result is not presented as
   unquestionable proof.

Use this sentence:

> “Every decision is explainable: the analyst sees the observed value, the
> threshold, the plain-language reason and the detector limitation.”

### 3:10–4:00 — demonstrate human control

Change the workflow status to **Investigating**. Enter a note such as:

```text
Repeated callback and abnormal outbound transfer verified during SIH demo.
```

Click **Malicious**, then click **Export evidence**.

Say:

> “Drastha assists the analyst; it does not silently make an irreversible
> decision. Status, notes, disposition and evidence remain available after a
> restart.”

### 4:00–4:35 — show broader coverage

Explain:

> “The current prototype also demonstrates reconnaissance, SYN and UDP flooding,
> DGA-like domains and DNS tunnelling. We do not train one ML model for every
> attack. We use behavioural and statistical detectors where rules are clearer,
> and a trained model where classification adds value, such as DGA detection.”

If requested, open `output/drastha_evaluation_report.json`. Point out that every
threat family is reported separately.

### 4:35–5:00 — close

> “Drastha converts passive one-way telemetry into an explainable, correlated
> and reviewable attack story. The demonstration is offline and repeatable today;
> production work will focus on deployment-specific calibration, scale,
> authentication and operational hardening.”

## 6. What is real and what is simulated?

| Component | Demo status |
|---|---|
| Attack traffic | Controlled synthetic Zeek-style capture |
| Telemetry parsing | Real code |
| Malformed/skew detection | Real code |
| C2 detection | Real behavioural detector |
| Exfiltration detection | Real baseline detector |
| Correlation and risk | Real deterministic logic |
| SQLite persistence | Real database |
| API and dashboard | Real application |
| Analyst feedback/export | Real workflow |
| Automatic blocking | Not implemented; intentionally outside passive scope |
| Production accuracy claim | Not claimed from synthetic fixtures |

## 7. Likely judge questions

### “Are you actually launching malware?”

No. We replay a safe, controlled telemetry fixture representing the observable
network behaviour. This is repeatable and avoids attacking any real device. The
complete analysis pipeline after telemetry creation is real.

### “Why not train an ML model for every attack?”

Not every problem benefits from ML. Port fan-out, connection floods, periodic
callbacks and outbound-volume deviations have interpretable behavioural
features. ML is used for the DGA classification task where character-pattern
generalization is useful. This hybrid approach is easier to explain and govern.

### “What does 100 risk mean?”

It is an investigation priority, not 100% certainty. It combines fixed threat
weights, a cross-detector bonus and a bounded confidence component. The formula
is visible in the incident.

### “Can it inspect encrypted traffic?”

It does not decrypt payloads. It can use visible metadata such as timing,
direction, sizes, TLS version, server name when available and fingerprints as
supporting context. A fingerprint alone cannot trigger a C2 alert.

### “What happens if telemetry is damaged?”

A small number of bad records are quarantined and reported as degraded. Missing
or excessively corrupt required streams become unavailable or unusable and block
the scenario. Drastha does not silently claim a clean result.

### “Does Docker have to work?”

No. SQLite is the primary dependable offline demo path. PostgreSQL and Docker
are supported deployment options, not presentation dependencies.

### “Is your accuracy production-ready?”

No production accuracy claim is made from the synthetic fixtures. The report
proves repeatable per-threat behaviour and prevents pooled metrics from hiding a
weak class. Production readiness requires licensed external datasets and
deployment-specific false-positive calibration.

### “Can it block an attack?”

The current solution is intentionally passive because a data-diode environment
has no return path. It produces reviewable evidence for an authorized response
system on the monitoring side; it does not violate the one-way boundary.

## 8. Emergency recovery

### Port 8000 is busy

```powershell
.\.venv\Scripts\python.exe -m aegisflow.cli demo-serve --fresh --port 8001
```

Then open `http://127.0.0.1:8001`.

### Docker is stopped

Ignore Docker and continue in SQLite mode.

### Zeek or WSL is unavailable

Continue with the bundled Zeek-style telemetry fixtures. Live PCAP conversion is
an optional extension, not a primary demo dependency.

### Incident does not appear

Click **Replay attack**, wait for the completion message, then press the refresh
icon. If telemetry is unavailable, run:

```powershell
.\.venv\Scripts\python.exe -m aegisflow.cli demo-preflight
```

### Browser/UI cannot be recovered

Open these backup evidence files:

- `output/drastha_demo_rehearsal.json`
- `output/drastha_evaluation_report.json`
- `output/drastha_ui_verification_report.json`

## 9. Final team checklist

- [ ] Laptop charged and sleep disabled
- [ ] One offline rehearsal completed
- [ ] `ready: true` confirmed
- [ ] Browser zoom set to 100%
- [ ] Notifications disabled
- [ ] PowerShell server window kept open
- [ ] Every member knows the attack-to-dashboard pipeline
- [ ] One member operates the UI while another speaks
- [ ] Backup reports copied to a separate folder or USB drive
- [ ] No production accuracy or automatic-blocking claims made
