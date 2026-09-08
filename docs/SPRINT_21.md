# Sprint 21 — family-separated DGA research iteration

## Outcome

Sprint 21 expands DGA research from Sprint 11's 12 UMUDGA families to a broader,
leakage-audited experiment. The candidate is **not production-approved**. It
improves validation behaviour substantially, but fails the conservative false-
positive uncertainty gate and then fails generalization on previously unseen
families. No dashboard/runtime model, detector threshold or mixed-replay result
was replaced.

The source is the publisher's [UMUDGA version 1](https://data.mendeley.com/datasets/y8ph45msv8/1),
which documents 50 DGA families, generated domain lists and MIT licensing. These
are publisher-generated domain labels, not proof of active infection or current
malicious infrastructure.

## Data separation

The checked-in `data/manifests/umudga_dns_v2.json` pins every source hash, split,
family, record count, model option, threshold and gate before final testing.

| Split | Positive families | Positive | Benign | Total |
|---|---:|---:|---:|---:|
| Train | 24 | 23,952 | 18,137 | 42,089 |
| Validation | 4 | 4,000 | 5,916 | 9,916 |
| Final test | 4 | 4,000 | 5,947 | 9,947 |

Sixteen train families are new to Drastha. Eight Sprint 11 train-only families
are reused only in training. Sprint 11 validation/test families never enter the
new validation or test. The final families—Rovnix, Shiotob, Simda and Tinba—were
selected before fitting and had not been used in the earlier experiment.

The legitimate source is the publisher's pinned 50,000-name list. Lines 1–10,000,
which formed Sprint 11's entire benign source, are excluded. Lines 10,001–40,000
are deterministically extracted and grouped by pinned Public Suffix List
registrable domain before the 60/20/20 assignment. Domains and malware families
cannot cross partitions.

## Model selection contract

The implementation remains inspectable character n-gram Naive Bayes. Sprint 21
adds bounded, predeclared architecture options:

- character n-gram sizes 2, 3, 4 and 5;
- repeated-frequency or binary-presence n-gram counts;
- multinomial sum or length-normalized mean log-likelihood scoring;
- 16 predeclared decision thresholds.

Only training rows fit model counts. Only validation rows select architecture
and threshold. Final-test labels/scores are absent from the candidate artifact.
The selected model uses character 2-grams, binary presence, multinomial scoring
and threshold 0.995. This selects an operating point; its output is still an
uncalibrated class score, not an infection probability.

## Validation result

| Metric | Result |
|---|---:|
| TP / FP / FN / TN | 2,854 / 54 / 1,146 / 5,862 |
| Recall | 71.35% |
| Precision | 98.14% |
| Point FPR | 0.91% |
| FPR Wilson 95% upper bound | 1.19% |

Overall and per-family recall gates pass, but the required FPR upper bound is at
most 1%. The candidate therefore failed validation before the holdout was opened.

## First frozen final-holdout result

The candidate and threshold were frozen before the test labels were scored.
`output/umudga_dns_holdout_v2_final.json` records:

| Metric | Result |
|---|---:|
| TP / FP / FN / TN | 1,704 / 67 / 2,296 / 5,880 |
| Recall | 42.60% |
| Precision | 96.22% |
| F1 | 59.05% |
| Point FPR | 1.13% |
| FPR Wilson 95% upper bound | 1.43% |

Per-family recall is Rovnix 0%, Shiotob 91.2%, Simda 8.6% and Tinba 70.6%.
This shows why a high aggregate precision cannot be presented as a successful
DGA detector. The holdout is now inspected and cannot be used for another tuning
round.

All 9,947 final records pass through `analyse_uploaded_replay`, the same shared
analysis function used by dashboard uploads. Quality is healthy, none are
rejected, classifier versus upload alert coverage is exactly equal, and no
unexpected subtype is emitted. Synthetic timestamps merely isolate domain
queries; they are not captured DNS timing or tunnelling evidence.

## Safety and promotion controls

- `scripts/fetch_umudga_v2.py` downloads plain text only, verifies publisher
  size/SHA-256 and never resolves or visits listed domains.
- Candidate/report output is create-only. Manifest, split and gate changes make
  frozen evaluation fail closed.
- Research artifacts keep `production_approved: false`; normal model loading and
  HTTP upload cannot activate them.
- The test split never participates in architecture or threshold selection.
- No automatic promotion exists even when dataset gates pass.

## Reproduction

```powershell
.venv\Scripts\python.exe scripts\fetch_umudga_v2.py
.venv\Scripts\python.exe -m aegisflow.cli fit-dns-candidate `
  --manifest data\manifests\umudga_dns_v2.json --data-root . `
  --candidate-output output\models\umudga_dns_candidate_v2_reproduction.json
.venv\Scripts\python.exe -m aegisflow.cli evaluate-dns-candidate `
  --candidate output\models\umudga_dns_candidate_v2_reproduction.json `
  --manifest data\manifests\umudga_dns_v2.json --data-root . `
  --report-output output\umudga_dns_holdout_v2_reproduction.json
```

Use new output names: prior experiments are never overwritten. Internet access
is needed only for explicit corpus setup, never for passive inference.

## Next work

Sprint 22 should treat DGA family morphology as a measured failure mode, test
contextual controls across all threat classes, and preserve this inspected
holdout. A future DGA iteration needs a new independent source/time holdout and
likely a stronger sequence model or calibrated ensemble; lowering gates is not
an acceptable fix.

## Regression verification

- Targeted DNS calibration/detector/mixed-replay suite: 30 tests passed.
- Full Python suite: 396 tests passed in 33.608 seconds.
- Frontend suite: 18 tests passed.
- TypeScript and Vite production build passed.
- Existing Starlette/httpx deprecation and frontend HMR-port warnings remain
  visible; no test, quality rule or promotion gate was weakened.
