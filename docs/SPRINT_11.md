# Sprint 11 — DGA corpus, operating-point selection and release safeguards

## Delivered scope and release decision

The DGA research/evaluation slice is implemented. **Production calibration is
not complete and the new model is not approved.** A real public domain corpus
exposed poor unseen-family recall; changing thresholds cannot repair this model's
generalization. No existing detector defaults, policies or demo model were replaced.

This sprint delivers reproducible training/validation/test controls, honest
failure gates and an actual upload-path evaluation. It does **not** deliver
calibrated infection probabilities, operational C2/exfiltration tuning, or a
validated production DGA detector. Those remain Sprint 11 follow-on work before
claiming production detection readiness.

## Public data and the reserved split

[UMUDGA version 1](https://data.mendeley.com/datasets/y8ph45msv8/1), by Zago,
Gil Perez and Martinez Perez (DOI 10.17632/y8ph45msv8.1), supplies labelled generated
DGA names and a publisher-labelled `legit` list. The publisher lists MIT licensing.
These are algorithm-generated domain lists, **not packet captures, current
destination reputation, infection labels or independently verified benign traffic**.

The checked-in manifest `data/manifests/umudga_dns_v1.json` pins 13 individual text
files, publisher file IDs, SHA-256 hashes, source/license/citation, split seed,
threshold grid and acceptance gates. Families were assigned before scoring:

| Partition | Positive domains | Publisher-legit domains | Total | DGA families |
|---|---:|---:|---:|---|
| Train | 7,996 | 6,032 | 14,028 | alureon, banjori, corebot, dircrypt, matsnu, necurs, padcrypt, ramnit |
| Validation | 1,962 | 1,952 | 3,914 | cryptolocker, suppobox |
| Reserved final test | 2,000 | 2,016 | 4,016 | gozi, locky |

Raw and unique totals are both **21,958**, with zero duplicate domains. Publisher
files named `1000.txt` for matsnu and suppobox actually contain 996 and 962 rows.
The manifest records their verified counts; no rows were deleted or fabricated.

Benign groups use SHA-256 of the fixed seed and registrable domain, modulo 100:
0–59 train, 60–79 validation, 80–99 test. Malware families remain whole in one
split; related variants must use the same reviewed family identity. Group names
are curated annotations, not automatically proven algorithm lineage.

An initial structural audit found that the legacy last-two-label approximation
collapses unrelated `co.uk` names. A pinned
[Public Suffix List](https://publicsuffix.org/list/) snapshot now supplies
registrable-domain groups, including private suffixes. The implementation follows
the [PSL rules](https://github.com/publicsuffix/list/wiki/Format): longest match,
wildcards, exceptions, ASCII/IDNA normalization and the default unknown-TLD rule.
Snapshot: `2026-09-02_06-03-53_UTC`, MPL-2.0, hash
`0e07be8daca66c85f12cf84827c6a9d09efd5950a89385621cf9df5c1c52e001`.
This grouping fix is confined to the research corpus, not a silent change to
legacy live DNS-tunnel/cooldown grouping.

## Model, threshold and confidence are different things

The existing inspectable **multinomial character 3-gram Naive Bayes** implementation
is trained only on training rows. It uses boundary-aware character counts,
Laplace smoothing and learned class priors. Python's standard library is enough;
no new ML dependency or executable malware code was introduced.

Research model input is the **full normalized DNS query**, identically in training
and runtime. Legacy models retain the previous two-label detector input. Full-query
research results do not imply robustness to unobserved subdomains or DNS campaigns.

`fit-dns-candidate` audits all split identities for leakage, passes only train rows
to fitting, and scores only validation rows. Test features/labels are used only by
the structural audit, not training or threshold selection. Candidate thresholds
are predeclared: 0.5, 0.9, 0.99, 0.999, 0.9999, 0.99999, 0.999999.

Acceptance requires at least 500 positive and 500 negative examples, an FPR
Wilson-95% upper bound at most 1%, overall recall at least 70%, and every positive
family's recall at least 50%. Eligible candidates maximize recall, then minimize
FPR, then threshold. When **none is eligible**, the runner retains a clearly failed
research candidate with minimum FPR, then maximum recall, then lower threshold.
This fallback is for recording the failed experiment, never for deployment.

The output freezes the model, effective threshold, corpus/split hashes, validation
results and gates under a candidate digest. Separate `evaluate-dns-candidate`
checks that digest and the unchanged manifest/splits before scoring the final test.
Outputs are create-only. Checksums detect drift/corruption; **they are not digital
signatures or protection against an operator rewriting and re-signing metadata**.

The selected threshold is attached to the exact model and is reflected in detector
evidence and effective session configuration/provenance. Research artifacts are
rejected by normal model loading, including HTTP upload. The trusted evaluator
can construct an isolated research session; uploaded JSON cannot supply one.
There is no automatic promotion, even if research gates pass.

**Threshold calibration is not probability calibration.** N-gram scores remain
uncalibrated class scores, not probabilities of infection. Reports include Brier
loss, log loss, ten-bin reliability and ECE as diagnostics—not a claim that fitting
a probability calibrator occurred. See the
[calibration distinction and data-separation guidance](https://scikit-learn.org/stable/modules/calibration.html).
Related domains violate IID assumptions, so Wilson intervals are descriptive;
neither a low measured FPR nor a high reported score is a deployment guarantee.

## Measured results — failed candidate, retained honestly

Candidate digest:
`0143ac2f4ae14b1f6c9504428cf102fbf267d7c83d77e48ae248c931cc631eb9`.
The complete validation trade-off and final results are committed in
`output/umudga_dns_holdout_v1.json`; raw domain lists and the model stay ignored.

| Population | Threshold | TP | FP | FN | TN | Recall |
|---|---:|---:|---:|---:|---:|---:|
| Validation, default comparison | 0.5 | 706 | 76 | 1,256 | 1,876 | 35.98% |
| Validation, failed fallback | 0.99999 | 32 | 0 | 1,930 | 1,952 | 1.63% |
| Final holdout, frozen fallback | 0.99999 | 18 | 0 | 1,982 | 2,016 | 0.90% |

Final holdout F1 is **1.784%**. Gozi recall is 0/1,000; locky recall is 18/1,000.
Zero observed FP and precision of 100% here **do not make this model usable**:
it missed 1,982 positive names. All validation candidates failed recall gates.
The frozen candidate also failed final recall gates. Production approval remains
false. Scores are poorly aligned with truth (holdout Brier 0.38564; ECE 0.37983).

No changes were made after inspecting the final holdout to improve these numbers.
That holdout is now inspected: another development iteration needs a newly
reserved final test. The previously inspected CTU-13 run was not used for tuning.

## Actual ingestion, dashboard path and safeguards

Every final-test domain is wrapped into Zeek-native-ish DNS metadata and processed
by **`analyse_uploaded_replay`**, the function used by the dashboard upload API:

`JSONL -> input parsing/quality -> shared session -> DNS -> findings/incidents -> report`.

The wrapper adds synthetic UTC event times 121 seconds apart, unique UIDs and
documentation-only endpoint addresses. It does not add evaluation labels, policy
hints, reputation or supplied ML scores. These are explicitly isolated query
experiments, **not recorded timing or a streaming-throughput benchmark**. Separation
keeps the DNS campaign/tunnelling windows from contaminating per-domain measurement.

Actual output: **4,016 accepted; 0 rejected; 0 duplicate UIDs; 0 timestamp
regressions; healthy telemetry**. Eighteen domain UIDs are covered by DGA alerts.
Normal deduplication merges them into **one finding and one incident** for the
common source. Those UI counts must not be confused with 18 domain-level TP.
No unexpected threat subtype occurred. Classifier and upload alert-coverage
TP/FP/FN/TN match exactly. The healthy flag was neither bypassed nor hard-coded.

Tests also exercise real temporary SQLite persistence and
`GET /api/analysis-runs/{run_id}`, verify threshold/input/provenance survive JSON
serialization, and verify the HTTP upload endpoint rejects a research model.
No production database was modified by the corpus run.

The original mixed fixture remains unchanged: **452 accepted, 8 findings,
8 incidents, 8 TP, 0 FP, 0 FN, 86 TN, healthy**. No detector thresholds were
changed to preserve or improve that fixture.

## Reproduce

From the repository root, in an explicit research/download environment:

```powershell
.venv\Scripts\python.exe scripts/fetch_umudga.py
.venv\Scripts\python.exe -m aegisflow.cli fit-dns-candidate --manifest data/manifests/umudga_dns_v1.json --data-root . --candidate-output output/models/umudga_dns_candidate_v1.json
.venv\Scripts\python.exe -m aegisflow.cli evaluate-dns-candidate --candidate output/models/umudga_dns_candidate_v1.json --manifest data/manifests/umudga_dns_v1.json --data-root . --report-output output/umudga_dns_holdout_reproduction.json
.venv\Scripts\python.exe -m unittest tests.test_dns_calibration tests.test_dns_detector tests.test_mixed_evaluation_replay -v
.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Already-existing candidate/report files are not overwritten: reuse the frozen
candidate for evaluation or choose a new output filename. Exact source files are
hash-verified. The public PSL URL changes over time; a different snapshot fails
closed and must not silently replace this experiment's pinned version. Retain the
verified local snapshot when reproducing the experiment offline. The downloader
never resolves, contacts or executes anything named inside the lists and is never
called from the passive ingest pipeline.

## Acceptance and remaining work

- Full suite: **216 tests passed** (196 existing + 20 new).
- Targeted calibration/DNS/mixed tests: **27 passed**.
- Frontend TypeScript/Vite build and `git diff --check`: passed.
- Existing Starlette/httpx deprecation warning remains non-failing.
- No browser visual inspection, live Zeek or live PostgreSQL validation was done.

Remaining Sprint 11 work: richer family-robust DGA development, separate probability
calibration data, fresh independent final holdouts, and feature-compatible labelled
captures for C2, TLS/QUIC, DNS tunnelling, DDoS, scanning and exfiltration. Operational
monitoring/backup/CDN traffic must be assessed before claiming real-world FP rates.
The current corpus cannot supply those timing, packet, TLS or policy features.
