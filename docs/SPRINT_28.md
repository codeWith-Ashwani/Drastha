# Sprint 28 — independent DGA holdout and fail-closed promotion

Sprint 28 tests whether the DNS DGA research model generalizes to malware families
that were not used for fitting or operating-threshold selection. It adds a hybrid,
inspectable character n-gram plus lexical classifier, a create-only official-data
acquisition workflow, and an explicit model-promotion gate. It does **not** claim
production accuracy and it does not change the deployed demo model.

## Frozen dataset contract

`scripts/fetch_umudga_v3.py` uses the official UMUDGA Mendeley API and pinned file
identifiers/checksums. It only downloads domain-list text files; it never resolves,
visits or transmits traffic to any domain. Raw licensed data remains ignored by Git.
The checked-in `data/manifests/umudga_dns_v3.json` reproduces the split contract.

- 87,829 unique domains; zero duplicate rows after construction.
- Train: 71,898 domains (30,000 benign, 41,898 malicious).
- Validation: 6,958 domains (4,958 benign, 2,000 malicious), with `sisron` and
  `symmi` reserved as validation-only malware families.
- Final test: 8,973 domains (4,973 benign, 4,000 malicious), with `tempedreve` and
  `vawtrak` reserved as single-use final-test families.
- Every malicious source previously inspected in Sprint 21 is train-only.
- Fresh benign registrable-domain groups are disjoint from historical benign
  groups and from all malicious sources. This guard caught and removed a real
  `mooo.com` group collision before model fitting.

The feature variants, thresholds and gates were declared in the manifest before
the final test was opened. The final test was not used to choose a feature weight,
n-gram size, count mode or threshold. Since it has now been inspected, further
tuning requires a new reserved final holdout.

## Hybrid model and selection

The model remains small and explainable:

- character 2/3/4-gram multinomial Naive Bayes;
- frequency or binary-presence counts;
- Gaussian class likelihoods for the existing lexical DNS features;
- six predeclared n-gram/lexical weight combinations;
- eleven predeclared decision thresholds.

Training learns n-gram and lexical statistics from train rows only. Candidate
selection scores validation rows only. A zero lexical weight preserves compatibility
with existing n-gram-only model artifacts. The score is still an uncalibrated class
score, not the probability that a host is infected.

The frozen candidate selected 3-grams, frequency counts, multinomial scoring,
`ngram_weight=0.75`, `lexical_weight=0.25`, and threshold `0.99`.

| Split | TP | FP | FN | TN | Recall | FPR | 95% FPR upper bound |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Validation | 1,775 | 31 | 225 | 4,927 | 88.75% | 0.625% | 0.886% |
| Final test | 1,380 | 29 | 2,620 | 4,944 | 34.50% | 0.583% | 0.836% |

Final-family recall was 76.90% for `tempedreve` and 20.37% for `vawtrak`. The test
therefore failed both the 70% pooled-recall gate and 50% per-family recall gate.
Upload-analysis prediction parity is exact and telemetry quality is healthy, so
this is a genuine generalization failure rather than an ingestion/display problem.

## Promotion control

`promote-dns-candidate` accepts only a create-only candidate and a checksum-bound
holdout report that match on candidate digest, corpus audit, gates, validation
result and candidate grid. It independently recomputes validation/test gate
failures and requires exact upload parity, healthy quality and no unexpected
detector subtype. It never edits deployment configuration automatically.

The Sprint 28 candidate is correctly rejected:

```powershell
.venv\Scripts\python.exe -m aegisflow.cli promote-dns-candidate `
  --candidate output\umudga_dns_candidate_v3.json `
  --evaluation output\umudga_dns_holdout_v3_bound.json `
  --model-output output\umudga_dns_promoted_v3.json
```

The command reports `recall_below_minimum` and
`family_recall_below_minimum:vawtrak`; no model file is created. Even a passing
corpus model would only receive `corpus_holdout_gates_passed` scope. Operator
deployment and deployment-representative validation remain separate decisions.

## Reproduction

```powershell
.venv\Scripts\python.exe scripts\fetch_umudga_v3.py
.venv\Scripts\python.exe -m aegisflow.cli fit-dns-candidate `
  --manifest data\manifests\umudga_dns_v3.json --data-root . `
  --candidate-output output\new_umudga_dns_candidate_v3.json
.venv\Scripts\python.exe -m aegisflow.cli evaluate-dns-candidate `
  --candidate output\new_umudga_dns_candidate_v3.json `
  --manifest data\manifests\umudga_dns_v3.json --data-root . `
  --report-output output\new_umudga_dns_holdout_v3.json
```

All outputs are create-only. Use new paths when reproducing an experiment.

## Remaining work

- Design a materially different DGA approach before reserving a v4 final holdout;
  do not tune this model against the now-inspected Vawtrak result.
- Add deployment/time/environment-separated benign DNS telemetry with authorized
  labels and measure operational false-alert load.
- Calibrate probabilities separately if probability semantics are required.
- Keep DGA scoring as supporting evidence alongside DNS campaign context; it is
  not a malware verdict by itself.
