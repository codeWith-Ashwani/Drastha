# Sprint 10 — independent evaluation and dataset controls

Completed: 4 September 2026. Scope: reproducible external validation and the
controls needed before calibration. **No detector thresholds were tuned, no
production model was promoted, and no production-accuracy claim is made.**

## Delivered

- `evaluate-corpus`: an offline CLI command with checksum-pinned artifacts,
  source/license/citation metadata and an explicit train/validation/test split.
- Capture/group and normalized-telemetry leakage checks before inference. One
  complete capture per artifact; no row-level random split or implicit sampling.
- Separate, checksum-pinned ground-truth sidecars for native Zeek JSONL. Inline
  evaluation labels and canned feature scores do not reach benchmark detectors.
- A CTU-13 detailed bidirectional Argus text-flow adapter, preserving direction,
  source label statistics, timezone assumptions and unavailable-feature warnings.
- Frozen deployment-baseline execution through `analyse_prepared`, the same
  completion path as dashboard uploads, with fresh state per capture. Demo policy,
  DNS model and environment overrides are not loaded implicitly.
- Binary alert-coverage and per-class confusion matrices, precision/recall/F1/FPR,
  bounded error examples and descriptive 95% Wilson intervals. Undefined metrics
  are `null`, not 100%. Wrong-class predictions contribute FN and FP.
- Optional persistence in a separate evaluation database; existing
  `/api/analysis-runs/{run_id}` exposes the report, evidence and benchmark scores.
- DNS dataset guards now cover train/validation/test family separation,
  case-normalized domain duplicates, conflicting within-split rows and direct
  model-training calls. The classifier mathematics and shipped model are unchanged.
- Dashboard text explicitly distinguishes uploaded fixture scores from independent
  production accuracy.

## Independent external experiment: CTU-13 scenario 11

The **whole** publisher-provided `capture20110818-2.binetflow` was downloaded from
the [authoritative CTU capture directory](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-52/detailed-bidirectional-flow-labels/).
Only text flow metadata was fetched; no executable, malware binary or payload
archive was downloaded or executed. The raw file remains ignored under `data/raw`.
The committed manifest and derived report contain attribution and checksums.

Source file: 14,596,615 bytes. SHA-256:

```text
cee542d4b5efe4fa1cd59b87ece5aaea9a13d8f0abe56cd07cee31590736428c
```

The publisher links [CC BY 2.0](https://creativecommons.org/licenses/by/2.0/).
Citation: Sebastian Garcia, Martin Grill, Jan Stiborek and Alejandro Zunino,
*An empirical comparison of botnet detection methods*, Computers & Security 45
(2014), 100–123, doi:10.1016/j.cose.2014.05.011.

The adapter converts the original Argus columns to canonical metadata. The
source bytes are unchanged; derived field mappings and missing features are
explicitly documented below. No author endorsement is implied.

### Results — not a successful detection benchmark

| Measurement | Result |
|---|---:|
| Input flows | 107,251 |
| Accepted flows | 106,976 |
| Rejected/quarantined | 275 |
| Timestamp regressions / duplicate UIDs | 0 / 0 |
| Findings / incidents | 40 / 24 |
| Labelled malicious flow units | 8,164 |
| Verified-normal flow units | 2,709 |
| Unknown/unscored units | 96,378 |
| Malicious units covered by alerts (TP) | 0 |
| Normal units covered by alerts (FP) | 15 |
| Malicious units without alert coverage (FN) | 8,164 |
| Normal units without alert coverage (TN) | 2,694 |
| Binary coverage precision / recall / F1 | 0 / 0 / 0 |
| Verified-normal flow-unit FPR | 0.5537% |
| Input quality | degraded |

These are **flow-membership-in-alert** metrics, not eight-behaviour detection
accuracy. 8,143 of the 8,164 malicious labels are ICMP; the existing DDoS
detectors target TCP SYN and UDP behaviours, not ICMP floods. The remaining
labels include DNS and sparse IRC/HTTP flows. Generic botnet labels do not
assert periodic C2 or an encrypted-session anomaly. Missing DNS names, TLS
fingerprints and packet sequences prevent validating those feature paths.

The 40 findings consist of 7 horizontal scans, 7 multi-host/port scans, 2 vertical
scans, 14 outbound-volume anomalies and 10 periodic callbacks. Some alerts cover
unknown/background traffic, which cannot be classified as TP or FP without more
ground-truth review. Fifteen FP **units are not fifteen independent incidents**.

The 275 rejected records include unsupported Argus protocol names and non-IP
addresses. They are not deleted from the source or silently counted as benign.
Original input quality stays degraded. The parser is not weakened to make this
capture healthy. A capture exceeding the existing unusable-quality threshold
fails the evaluation rather than receiving fabricated scores.

The full report is `output/ctu13_scenario11_benchmark.json`. One finite end-to-end
run took about 51 seconds, including loading, auditing and inference. This is
not a sustained throughput or live-latency test.

Scenario 11 is now **inspected evaluation data**. Future work must not tune to
its scores and then describe it as an untouched holdout. No training or
validation corpus was used in this frozen-rule experiment. A registered `test`
split alone is not proof of independent model validation.

## Reproduce

From the repository root, with the exact source file present at the manifest path:

```powershell
.venv\Scripts\python.exe -m aegisflow.cli evaluate-corpus --manifest data/manifests/ctu13_scenario11_benchmark.json --data-root . --report-output output/ctu13_scenario11_benchmark.json
```

The runner is offline: it does not download files. A missing file, hash mismatch,
invalid sidecar or split leak fails before inference. `--database
output/evaluation.db` additionally stores the ordinary findings and enriched run
report. Use a separate evaluation database to avoid polluting operational queues.
Without that option, no database is implicitly created. A returned run ID is
queryable through the API only when the run was persisted.

Output paths may not overwrite the manifest, source, sidecar, model or each other.
The CLI exits 0 for a completed experiment, **not** for good detection accuracy;
always inspect quality, denominators and metrics. Invalid experiments exit 2.

## Manifest and labels contract

`schema_version` is `drastha-corpus-v1`. Each artifact declares `id`, unique
`capture_id`, nonempty `group_ids`, `split`, `format`, relative `path`, SHA-256,
and origin kind (`synthetic` or `external`). External origin additionally requires
source URL, license, license URL, citation and timezone-aware retrieval time.
Optional `expected_records` verifies the complete pinned record count.

Group IDs should include actual malware/service families, capture lineage and
environment identities. Shared groups cannot appear in different splits. Exact
normalized observations are also checked across splits independently of UID,
label, aliases and optional-field defaults. All registered splits are audited,
but only the requested split is executed. Capture filenames/group declarations
cannot prove that an operator supplied complete data or disclosed every common
entity; source review remains necessary.

Native format is `zeek-jsonl`, one canonical record per unique nonempty UID.
Its `labels` descriptor points to a separately pinned JSON document:

```json
{"units":[{"unit_id":"scan-1","flow_ids":["C1","C2"],"label":"attack","expected_classes":["reconnaissance_port_scan"]}]}
```

Labels are `attack`, `benign` or `unknown`. Only attacks have expected classes.
Units must be disjoint and reference existing input UIDs. Unlabelled records
become explicit unknown units. Unit grouping must be declared independently of
predictions. Labels do not reset detectors or control traffic ordering.

Classes follow `evaluation_scoring.EXPECTED_SUBTYPES`, plus generic UDP flooding
and `any_attack`. `any_attack` is intentionally not equivalent to any specific
threat subtype. The historical `encrypted_session_malware` evaluation key means
the expected **metadata anomaly**, not definitive malware identification.

Native input uses a canonical metadata allowlist. Arbitrary `features`,
`ml_evidence`, inline labels and policy-like fields are not imported. Raw
`packet_observations` are allowed and evaluated by the measured feature extractor.
Unlike demo uploads, benchmark runs cannot get a TLS result from supplied anomaly
scores. If the optional DNS model is used, its file hash and training-group IDs
must refer to audited training groups; this records declared lineage, not a
cryptographic proof of what trained the model.

## CTU adapter assumptions and exclusions

- `StartTime` has an explicit manifest UTC offset: +120 minutes for this capture's
  CEST timeline. The experimental internal boundary is explicitly 147.32.0.0/16;
  it is not an automatically discovered asset inventory.
- Source/destination addresses and ports are Argus observation orientation, not
  guaranteed TCP initiator/responder. Source bytes and `TotBytes-SrcBytes` are
  directional Argus byte volumes, not asserted Zeek application-payload counts.
- Argus `State` is **not** converted into Zeek `conn_state`. Total packet count
  is **not** invented as per-direction packet counts. ICMP fields are not ports.
- Only `From-Botnet` is treated as generic malicious, and `From-Normal` as
  verified normal. Other labels, including `To-Botnet`, `To-Normal`, standalone
  `Normal-*` and Background, remain conservatively unknown in this adapter.
  Original label counts are retained. The publisher explicitly cautions against
  equating `To-Botnet` with malicious traffic in the
  [capture documentation](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-52/).
- DNS names, SYN packet/state features, TLS/QUIC fingerprints and packet sequences
  cannot be reconstructed from this table. Missing evidence is not benign.

## Statistical and implementation limits

Metrics use declared units, so repeated alerts on one unit do not inflate FP.
Known wrong subtypes generate FN for the expected class and FP for the observed
class. Unknown units stay in detector history but outside labelled denominators.
Rejected labelled units remain visible; rejected attacks cannot disappear from
the FN denominator. Recall/FPR intervals use the
[Wilson formula](https://www.itl.nist.gov/div898/handbook/prc/section2/prc241.htm).
Related flows are not independent trials, so these intervals are descriptive,
not deployment confidence guarantees. Pooled results must not hide per-capture
or per-class weaknesses.

This adapter limits each file to 64 MB, each corpus to 500,000 records and 100
artifacts. It processes finite captures in memory. It does not fetch archives,
run active probes, decrypt traffic, train models, perform threshold search or
calibrate probabilities. Declared groups are not inferred malware-family truth;
retimestamped/edited copies and undeclared training lineage require review.

## Acceptance and remaining work

- Full suite: 196 tests passed (168 existing plus 28 new at completion).
- Targeted `tests.test_benchmark tests.test_mixed_evaluation_replay`: 29 passed.
- `pnpm run build` in `web`: TypeScript/Vite build passed. `git diff --check`
  passed. Existing Starlette/httpx deprecation warning remains non-failing.
- Actual CLI, shared upload-analysis completion, SQLite persistence/API readback,
  poisoned inline labels, rejected-unit denominators, hash/path protection,
  normalized duplicate/group leakage and DNS split guards are regression-tested.
- Original mixed demo: 452 accepted / 8 findings / 8 incidents / 8 TP / 0 FP /
  0 FN / 86 TN / healthy; demonstration thresholds and fixture unchanged.
- CTU external run reproduced with unchanged source checksum and the weak results
  shown above; no threshold changes were made after inspecting them.

No new browser visual inspection, live Zeek conversion or live PostgreSQL test
was performed for this sprint. The shared HTTP report endpoint is tested with
FastAPI's test client and a real temporary SQLite database.

Sprint 11 must acquire **feature-compatible** labelled development/validation
captures and an independent final holdout before calibration. It should measure
false positives on operational services, tune only on development/validation
data, and clearly separate unsupported ICMP/generic-malware coverage from the
project's stated attack families. CICDDoS2019's citation requirement was reviewed,
but its data was not downloaded/evaluated here. Public DGA training data and
independent held-out DGA calibration are also still outstanding. The existing
synthetic DGA model is not replaced or promoted by this sprint.
