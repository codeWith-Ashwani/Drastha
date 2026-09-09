# Sprint 29 — family-blocked DGA model development

Sprint 29 responds to Sprint 28's unseen-family recall failure without tuning on
the inspected final holdout. An inventory of the official UMUDGA release showed
that every available malware family had already appeared in a Sprint 11, 21 or 28
experiment. Creating another “fresh UMUDGA test” would therefore be leakage.

This sprint builds and evaluates a materially different classifier on the already
inspected corpus, explicitly as model-development evidence. It emits no candidate,
cannot pass the promotion workflow, and does not change the demo or deployment
model.

## New classifier

`DNSHashedLogisticModel` is a deterministic sparse logistic classifier:

- signed BLAKE2b feature hashing into 4,096 bounded coordinates;
- character 2-, 3- and 4-grams with per-domain L2 normalization;
- eight standardized and clipped lexical features;
- equal class and equal malware-family contribution weighting;
- four deterministic SGD passes, learning rate 0.08 and L2 0.0001;
- no runtime dependency on NumPy, scikit-learn or an external service.

Feature hashing bounds model memory and avoids storing sensitive or attacker-chosen
domain strings in the model. The research artifact is fail-closed: normal runtime
loading rejects `research_status: not_approved`. Existing n-gram model loading and
the deployed demonstration model are unchanged.

## Family-blocked evaluation

`scripts/evaluate_dns_logistic_development.py` merges the already inspected v3
train/validation/test rows only for development cross-validation. It assigns each
malware family wholly to one of three deterministic folds. Benign rows are assigned
by Public Suffix List registrable-domain group, preventing related subdomains from
crossing folds.

- 87,829 records and 87,829 unique domains;
- 40 malware family labels, each confined to one validation fold;
- 39,802 benign registrable-domain groups;
- fold sizes: 32,130 / 27,402 / 28,297;
- every row receives exactly one out-of-fold prediction;
- output report is create-only and checksum-bound;
- `promotion_eligible` and `production_approved` are always false.

## Honest result

The development grid produced the following main trade-off:

| Threshold | Recall | FPR | TP | FP | FN | TN |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0.50 | 80.77% | 6.96% | 38,687 | 2,781 | 9,211 | 37,150 |
| 0.70 | 70.86% | 2.66% | 33,939 | 1,060 | 13,959 | 38,871 |
| 0.80 | 63.66% | 1.38% | 30,491 | 550 | 17,407 | 39,381 |
| 0.90 | 52.47% | 0.52% | 25,134 | 206 | 22,764 | 39,725 |

No operating point satisfies the unchanged 1% conservative FPR, 70% pooled recall
and 50% per-family recall gates together. At threshold 0.50, `matsnu`, `nymaim`,
`simda` and `vawtrak` remain below the per-family recall floor. This is useful
negative evidence: replacing Naive Bayes with a family-balanced linear classifier
does not solve cross-family generalization.

The repeat run produced byte-identical output (SHA-256
`88b99b4c7cc7a6e6bc891ca79978fb27ad343e7ec6a49cfef988e558a91b39bc`).
Per-training-fold feature caching reduced the observed local run from roughly 132
seconds to 95 seconds without changing any score or result. These timings are local
development observations, not throughput claims.

## Reproduction

```powershell
.venv\Scripts\python.exe scripts\fetch_umudga_v3.py
.venv\Scripts\python.exe scripts\evaluate_dns_logistic_development.py `
  --report-output output\new_sprint29_dns_logistic_development.json
```

The checked-in result is `output/sprint29_dns_logistic_development.json`.

## Decision and next gate

The model is retained as an inspectable research implementation but is rejected as
a deployment candidate. Sprint 30 must source or construct a legally usable,
independent DNS dataset separated by publisher or collection environment. Model or
threshold selection must occur before that new final test is opened. Operational
DNS telemetry, prevalence and campaign context remain necessary even if a future
domain classifier passes its corpus gates.
