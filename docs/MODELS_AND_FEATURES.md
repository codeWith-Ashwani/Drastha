# Models, engineered features, and validation approach

## Detection strategy

Drastha deliberately uses a hybrid architecture. ML is used where learned lexical
patterns add value; transparent behavioural and statistical detectors are used
where the relevant behaviour has a direct measurable definition. This avoids a
single opaque traffic-to-attack model and keeps every finding explainable.

## DGA model

The implemented supervised model is a Bernoulli/Multinomial-style Naive Bayes
classifier over normalized domain character 3-grams.

### Input and features

- normalized approximate registered domain;
- boundary-aware character 3-grams;
- contextual lexical values: length, entropy, digit ratio, vowel ratio, label
  count, maximum label length, hyphen ratio, and unique-character ratio.

The n-gram probabilities create the ML score. Lexical values are shown as evidence.
A guarded fallback requires several distinct digit-heavy, high-entropy, low-vowel
domains from one source inside a window; one random-looking domain is insufficient.

### Training and validation

`drastha train-dns` performs:

1. CSV loading and normalization;
2. duplicate-domain checks;
3. malicious-family leakage checks;
4. predefined train/test separation;
5. model fitting;
6. precision, recall, F1 and confusion-count calculation;
7. versioned JSON model, metrics, dataset manifest and model-card output.

The bundled dataset is intentionally small and synthetic. Its metrics validate the
training/inference machinery, not real-world accuracy. Production validation must
use licensed benign-domain and DGA-family datasets with family-separated holdouts.

## DNS tunnelling

This is a stateful statistical detector, not a supplied label lookup. It measures
queries per source/base-domain window, unique left labels, average label length,
entropy, and TXT-query ratio. A strong encoded-TXT path still requires repeated
queries plus both length and entropy evidence; this path covers shorter encoded
labels when repetition, TXT concentration, uniqueness, and entropy agree.

## DDoS

The DDoS detector measures flow arrival rate, incomplete-flow ratio, target-port
concentration, packet/byte volume, response/request amplification, source diversity,
and normalized source-IP entropy. High port fan-out is suppressed as reconnaissance.
High source entropy produces a distributed-source SYN subtype. Passive flow metadata
cannot prove spoofing, so the classifier deliberately makes no spoofing claim.

## C2 beaconing

The detector groups completed flows by source, destination, port, and protocol. It
measures mean inter-arrival time, interval coefficient of variation, transfer-size
coefficient of variation, observation span, mean transfer size, and completed-flow
ratio. Short normal HTTPS bursts and large repeated downloads are rejected. Visible
TLS metadata may enrich context but timing/size behaviour remains mandatory. Port 53
or DNS-service flows are routed only to DNS analytics. A trusted monitoring-side
endpoint policy acts as a negative signal, never a positive trigger.

## Encrypted-session anomaly

TLS/QUIC payload is never decrypted. A finding requires repeated sessions with the
same JA3/JA4 identity, low fingerprint prevalence, high packet-size-sequence anomaly,
and high timing-sequence anomaly. Fingerprint rarity by itself cannot alert.

## Reconnaissance

Sliding windows count destination ports per target, destination hosts per service,
and combined port diversity across multiple hosts. Streaming alerts fire at threshold
crossing and are preserved throughout completed replay analysis. A final-window
snapshot may enrich a still-active finding but cannot replace historical detections.

## Exfiltration

The detector combines outbound byte volume, outbound/inbound ratio, per-source median
baseline, baseline multiplier, destination context, and cooldown. A separate extreme
single-flow path requires at least 10 MB outbound and a 20:1 direction ratio. Approved
backup destinations are suppressible, and benign balanced downloads are tested. A
baseline-free multi-flow path requires at least three flows whose aggregate exceeds
10 MB and 20:1, preventing the baseline from learning the suspicious burst itself.

## Operational context policy

`config/context_policy.json` contains exact source, destination, destination-port,
protocol, service, and purpose rules for approved periodic services and bulk-transfer
endpoints. It is loaded from the monitoring enclave, not learned from replay labels.
`DRASTHA_CONTEXT_POLICY` may point to a deployment-specific policy file. Uploaded
fields such as `ml_label`, `scheduled_health_check`, or `approved_backup` cannot
suppress an alert. Policy matches and suppression counts are exposed in replay output
for auditability. Rules must be change-controlled because an overly broad approval
can hide genuinely malicious traffic.

## Confidence, severity, and risk

- **Confidence** measures how strongly the observed features satisfy one detector.
- **Severity** is the detector/policy impact category.
- **Risk score** prioritizes a correlated incident using distinct threat weights,
  detector agreement, and a bounded confidence contribution.

Risk 100 means investigate first; it does not mean 100% certainty.

## Validation policy

- Every detector has malicious and benign regression tests.
- Scenario fixtures are deterministic and expected subtypes are explicit.
- Supplied ground-truth labels are ignored during inference.
- Synthetic results are never presented as production accuracy.
- Real accuracy, false-positive rate and calibration remain deployment work.
## Sprint 9 measured-feature update

The deployment-baseline profile now derives encrypted-session prevalence and
sequence scores from preceding passive observations rather than accepting canned
anomaly scores. It uses robust unsupervised statistics, not a new supervised
malware model. The demonstration profiles retain explicitly labelled supplied
score compatibility. For formulas, cold start, supported PCAP/JA3 scope, network
direction and limitations, see [Sprint 9](SPRINT_9.md). Older supplied-feature
examples below remain demonstration inputs, not evidence of measured accuracy.
