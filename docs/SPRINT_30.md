# Sprint 30 — independent ExtraHop DGA evaluation

Sprint 30 evaluates the frozen Sprint 28 DGA candidate against a different
publisher's labelled corpus. It does not reuse ExtraHop data for training,
feature selection or threshold selection. The result is an independent
cross-publisher generalization check, not a production-traffic accuracy claim.

## Source and licence

The source is ExtraHop Networks' public DGA Detection Training Dataset at commit
`aa208020259c6a4e7b9aa838ebd7b48ad6f4a3a3`. The repository describes an
approximately balanced corpus of passively harvested or synthesized benign/DGA
core strings. It is distributed under the MIT licence.

The complete 170,860,023-byte gzip is pinned by SHA-256
`536c3292c95f405219ee6851fc89d4cb6c36406fe2c0bb89a950bce22aa5d8ab` in
`data/manifests/extrahop_dga_v1.json`. Raw data remains ignored by Git. The
acquisition path downloads only the pinned file and never resolves or visits any
contained domain.

The streamed source contains 16,246,006 labelled JSON records and five comment or
blank lines. This is eight fewer records than the 16,246,014 stated in the source
README, so Drastha records the measured count rather than silently substituting the
published description.

## Frozen sample and compatibility contract

Before reading labels for scoring, the evaluation contract fixed:

- seed `drastha-sprint30-extrahop-independent-v1`;
- SHA-256 smallest-hash sampling;
- 20,000 benign and 20,000 DGA records;
- a 1% deterministic oversample population;
- exact UMUDGA core-string overlap exclusion;
- the frozen Sprint 28 candidate and its threshold 0.99;
- no synthetic TLD appended to publisher strings.

The full gzip is streamed with bounded memory. Structural JSON/schema errors fail
with their line number. The audit excludes 2,035 underscore/otherwise invalid DNS
host labels while retaining that exact count. It excludes 36,379 source rows whose
core string overlaps UMUDGA before selecting the sample. The resulting 40,000
domains are unique; sample SHA-256 is
`b8106b16fda61bababb0b78258c7ada342669f47dce9552844ed2157710c3a07`.

ExtraHop deliberately omits TLD/country-code data and malware-family labels.
Drastha evaluates each published core string unchanged. Appending a made-up suffix
would create an uncontrolled model feature. Consequently, this test cannot prove
full-query compatibility or per-family recall, and promotion remains blocked even
if numeric pooled gates were to pass.

## Actual result

| TP | FP | FN | TN | Precision | Recall | F1 | FPR | FPR 95% interval |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 12,671 | 1,359 | 7,329 | 18,641 | 90.31% | 63.36% | 74.47% | 6.80% | 6.45–7.15% |

The unchanged 70% recall and conservative 1% FPR gates both fail. The result
confirms that the UMUDGA candidate does not generalize adequately to this different
publisher distribution.

The dashboard upload wrapper correctly refused a single replay above its 5 MB demo
limit. The evaluator therefore uses five bounded 8,000-record uploads rather than
bypassing the limit. All 40,000 records were accepted, zero were rejected, every
chunk reported healthy quality, and aggregated upload TP/FP/FN/TN exactly match
direct classifier inference. No unexpected detector subtype appeared.

## Fail-closed status

The checked-in report is checksum-bound and records:

- `dataset_numeric_gates_passed: false`;
- `promotion_eligible: false`;
- `production_approved: false`;
- recall and FPR gate failures;
- permanent blockers for absent family/TLD metadata and absent deployment context.

No model artifact or deployment configuration changed.

## Reproduction

Generate the ignored Sprint 28 candidate first, then run:

```powershell
.venv\Scripts\python.exe scripts\evaluate_extrahop_dga.py `
  --fetch `
  --candidate output\umudga_dns_candidate_v3.json `
  --report-output output\new_sprint30_extrahop_dga_evaluation.json
```

If the direct large-file transfer is unavailable, clone the pinned repository with
Git LFS and pass its gzip through `--source`. Existing reports are never
overwritten.

## Next gate

Domain-string ML alone has now failed both unseen UMUDGA families and an independent
publisher distribution. The next DGA improvement should combine the score with
passively measured DNS campaign features such as client prevalence, NXDOMAIN rate,
query bursts, answer diversity and recurrence. A future labelled evaluation must
preserve those event-level fields; a bare domain list cannot validate that layer.
