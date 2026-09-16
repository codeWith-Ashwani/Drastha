# Sprint 38 — independent CTU DGA training and upload-path holdout

## Outcome

This sprint tried to close the last SIH acceptance gap without changing detector
thresholds, weakening the quality monitor, or making the dashboard claim success.
It did **not** promote a new model.

The independent source is the Stratosphere Laboratory DNS Threats Dataset v1.
Its official compressed test file was downloaded and checksum-pinned before
model inference. A deterministic prediction-blind fixture contains 2,000 DGA and
2,000 benign domain strings; DNS-tunnelling rows are excluded because this gate
measures only DGA classification.

## Frozen protocol

- Source test SHA-256: `028fd97a4c498e8b6f22b93c2f804e4e0f3afe0c15ff5b3e71f9a12d0ddd4783`
- Fixture SHA-256: `533ad2b1e6ed5154720515f9a6c0f463b58bb7c15c961ff1b1a7f7ecdac80491`
- Sample: 2,000 DGA + 2,000 benign distinct normalized domains
- Gate: recall at least 70%, false-positive rate at most 1%
- Upload quality requirement: all 4,000 accepted, zero rejected, `healthy`

`scripts/freeze_sih_ctu_dga_holdout.py` reproduces the fixture from the ignored
raw source. The committed label contract says `frozen_before_inference: true`,
and the freeze manifest records `inference_run_at_freeze: false`.

## Training

The official training file is independently pinned at SHA-256
`9bc7c1e53d67c2b5ad9352a45bc415107521da10e96572d0ed5e4586b80e4de9`.
`scripts/fit_sih_ctu_dga_candidate.py` uses 40,000 rows per class for fitting and
10,000 per class for validation. It searches the already-supported inspectable
character n-gram Naive Bayes variants, lexical weights and thresholds. It never
opens the official test fixture.

The selected binary-presence 3-gram/lexical candidate passed internal validation:

| Metric | Validation result |
| --- | ---: |
| TP / FN | 7,728 / 2,272 |
| FP / TN | 63 / 9,937 |
| Recall | 77.28% |
| FPR | 0.63% |

The artifact is marked `research_status: not_approved`, remains gitignored, and
normal `DNSNgramModel.load` refuses research artifacts.

## Frozen test result

`scripts/check_sih_ctu_dga_holdout.py` scores the domains directly and then runs
the same records through `analyse_uploaded_replay`. Unique passive client
identities isolate the domain-model decision from campaign aggregation. Direct
and upload-path confusion matrices must match.

| Model | TP | FP | FN | TN | Recall | FPR | Gate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Deployed demo | 179 | 33 | 1,821 | 1,967 | 8.95% | 1.65% | Fail |
| CTU research candidate | 1,376 | 2 | 624 | 1,998 | 68.8% | 0.1% | **Fail** |

The candidate reduced false positives substantially and improved recall, but it
missed the frozen recall gate by 1.2 percentage points. The test fixture and
threshold were not altered after seeing that result. `output/models/dns_dga_demo.json`
therefore remains the deployed demonstration model, and the SIH final gate must
continue to report the DGA generalization limitation.

## Evidence boundary

This dataset contains domain strings and class labels. It does not contain
resolver responses, per-client campaigns, infection ground truth, or real-time
packet capture. It validates domain classification and the upload wrapper, not
operational infection detection. Drastha's resolver-outcome campaign detector is
separate and remains the safer route for word-like or unseen DGA families.

Primary source: [Stratosphere DNS Threats Dataset](https://mcfp.felk.cvut.cz/publicDatasets/DNS-Threats-Dataset/),
published as dataset DOI `10.5281/zenodo.6508640`.
