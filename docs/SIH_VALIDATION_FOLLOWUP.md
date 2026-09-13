# SIH validation follow-up — DGA context and measured TLS-positive control

This follows [Sprint 37](SPRINT_37.md). It is a bounded correction of the two
recorded evidence gaps, **not** a claim of production-grade model accuracy.

## TLS: measured positive without decryption

The previous real TLS capture changed protocol version/fingerprint but its first
packet window had normal size and timing. The PCAP adapter now retains the most
recent 128 packets per flow (rather than just the first 128), and
`PassiveFeatureExtractor` scores the **last observed packet window** of a completed flow using an inclusive
upper-quartile of per-position robust deviations. This captures post-handshake
encrypted-record sizes and pacing while ignoring a lone noisy packet. The
detector's rarity, size, timing and repeated-session thresholds were not lowered.
The capture join moves event time to the last retained packet; it does not look
ahead relative to that event or decrypt a byte. The extractor version changes to
`packet-sequence-tail-robust-v2`.

`scripts/generate_sih_tls_positive_capture.sh` ran in a no-default-route WSL
namespace. Source labels and intended contrast were written **before** inference:
110 normal TLS 1.2 sessions, four TLS 1.2 sessions with a different rare cipher
but otherwise normal exchanges, and eight TLS 1.3 sessions with four larger,
paced encrypted exchanges. Zeek emitted 122 connection and 122 SSL records;
`scripts/freeze_sih_tls_positive.py` pinned their raw PCAP/Zeek/client hashes and
created a 244-record chronological mixed fixture without labels or scores.

The actual `analyse_replay_file(..., packet_capture=...)` result is healthy,
244 accepted / zero rejected, **4 positive-control sessions covered by one alert,
zero false alerts across 114 benign sessions**, and 22 fully derived feature
sessions. The first four positive controls are warm-up/threshold-crossing misses,
so we report 4 TP / 4 FN / 0 FP / 114 TN at session attribution level—not 8/8.
Alert evidence includes PCAP SHA-256, JA3, prior baseline count, per-flow sequence
hashes, rarity and measured size/timing scores. No supplied compatibility scores
or payload decryption were used. This proves a **lab encrypted-session anomaly
control**, not malware identification.

## DGA: context improvement and model-promotion failure

The frozen 40 Vawtrak / 40 benign bare-domain test remains **0 TP / 40 FN /
2 FP / 38 TN**. It has no resolver response telemetry. A word-like DGA family
cannot be reliably distinguished from ordinary names by the deployed tiny
n-gram demonstration model, and we did not alter those records or relax quality.

The DNS detector now adds a separate *campaign* path requiring at least 12
same-client queries, 10 distinct roots and an 80% observed NXDOMAIN ratio inside
60 seconds. It also requires multiple distinct model-positive roots when a
resolver outcome is available; one positive n-gram score no longer creates an
alert by itself. Missing/`UNKNOWN` resolver status preserves the legacy model
route and its measured failures. The model probability threshold did not change.
Evidence and dashboard detection-method labels distinguish model corroboration
from DNS failure/fan-out. Authorized policy still applies separately.

Two labelled controls were frozen before inference. The first replays publisher
Vawtrak and legitimate strings with explicitly **simulated** DNS outcomes:
one DGA behaviour TP and two benign behaviour TN, zero FP. The second uses a
first-use 10,000-row sample from the [Chrmor research dataset](https://github.com/chrmor/DGA_domains_dataset)
at commit `9dcc29e5cc644fdfd99d82a3abec993c15bbc7bc`, source SHA-256
`8e6ed2cce7cf9230c92401748847c3955b53cca355fa568263aadd615e1e1ef1`.
An independently frozen 100-name Kraken burst and two disjoint 100-name Alexa
controls again give **1 behaviour TP / 0 FP / 0 FN / 2 TN**, healthy upload.
Publisher names were never resolved/contacted by Drastha. The chosen NXDOMAIN/
NOERROR outcomes and timing are *simulated resolver controls*, not measurements
provided by the publisher. These results validate the contextual detector path,
not domain-only accuracy or live resolver generalization.

A separate research-only 3-gram/lexical candidate was fitted on UMUDGA v3 train
plus its already-inspected old test families; Sisron/Symmi stayed validation-only.
The decision threshold came **only** from that validation split. Validation was
1,786 TP / 29 FP / 214 FN / 4,929 TN (89.3% recall, 0.585% FPR). The frozen
100 Kraken / 100 Alexa *domain-only* evaluation was 82 TP / 2 FP / 18 FN /
98 TN (82% recall, **2% FPR**). This exceeds the unchanged 1% FPR gate and the
external sample is too small for the 1,000-positive/negative promotion minimum.
The candidate is marked `research_status: not_approved`; `DNSNgramModel.load`
rejects it and the deployed demonstration artifact/configuration are unchanged.
The 1.1 MB trained candidate artifact remains local/gitignored; the committed
script and hash-bound report reproduce it from pinned raw sources.
The external publisher sample had also been used for campaign-context validation,
so this is not a pristine model-selection-independent publisher audit.

## Gate status and reproduction

`scripts/check_sih_final_gate.py` reruns the old SIH release acceptance, frozen
Gate 2 captures, new DNS campaign/Chrmor controls, new TLS PCAP control, full
Python/frontend suites and dashboard build. Current result: **functional SIH
prototype verified**, 462 Python tests and 19 frontend tests pass, but
`fresh_published_dga_detection` remains false. The gate exits nonzero and does
not create or promote a release. Old Sprint 36/37 failed reports remain as
historical evidence; their claims were not overwritten with the new lab score.

The raw Chrmor sample and TLS PCAP/key are gitignored. The committed fixtures,
label sidecars, SHA-256 manifests, source scripts and audit JSONs permit portable
derived-file verification. Full PCAP/publisher-source revalidation needs local raw
artifacts or a fresh separately labelled generation. No physical data diode,
field sensor or operational DGA accuracy is claimed.
