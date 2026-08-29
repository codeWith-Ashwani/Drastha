# AegisFlow DNS DGA model card

## Purpose

Demonstrate an inspectable character 3-gram Naive Bayes classifier for DGA-like DNS names.
It provides supporting evidence only and must not be treated as proof of malware.

## Data and split

- Dataset: `dns_training_demo.csv`
- Training examples: 20
- Test examples: 12
- Duplicate domains are rejected across splits.
- Malicious families are rejected when shared between train and test.

## Measured smoke-test results

- Accuracy: 1.0
- Precision: 1.0
- Recall: 1.0
- F1: 1.0
- Confusion matrix: {'tp': 6, 'fp': 0, 'tn': 6, 'fn': 0}

## Limitations

- The bundled data is a tiny synthetic fixture for pipeline verification, not a benchmark.
- Production training requires versioned public benign and DGA sources with licence review.
- CDNs, hosted services, tracking domains and newly registered legitimate names can cause false positives.
- DNS-over-HTTPS and other encrypted DNS are invisible unless telemetry is available before encryption.
- Scores are not calibrated probabilities on a real deployment population.
