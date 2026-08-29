from __future__ import annotations

import json
from pathlib import Path

from aegisflow.dns_model import DNSNgramModel, evaluate_dns_model, read_dns_dataset


def train_and_evaluate(
    dataset: str | Path,
    model_output: str | Path,
    metrics_output: str | Path,
    model_card_output: str | Path,
) -> dict:
    rows = read_dns_dataset(dataset)
    model = DNSNgramModel.train(rows)
    metrics = evaluate_dns_model(model, rows)
    model.save(model_output)

    metrics_path = Path(metrics_output)
    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    metrics_path.write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    training_count = sum(row.split == "train" for row in rows)
    test_count = sum(row.split == "test" for row in rows)
    card = f"""# AegisFlow DNS DGA model card

## Purpose

Demonstrate an inspectable character 3-gram Naive Bayes classifier for DGA-like DNS names.
It provides supporting evidence only and must not be treated as proof of malware.

## Data and split

- Dataset: `{Path(dataset).name}`
- Training examples: {training_count}
- Test examples: {test_count}
- Duplicate domains are rejected across splits.
- Malicious families are rejected when shared between train and test.

## Measured smoke-test results

- Accuracy: {metrics['accuracy']}
- Precision: {metrics['precision']}
- Recall: {metrics['recall']}
- F1: {metrics['f1']}
- Confusion matrix: {metrics['confusion_matrix']}

## Limitations

- The bundled data is a tiny synthetic fixture for pipeline verification, not a benchmark.
- Production training requires versioned public benign and DGA sources with licence review.
- CDNs, hosted services, tracking domains and newly registered legitimate names can cause false positives.
- DNS-over-HTTPS and other encrypted DNS are invisible unless telemetry is available before encryption.
- Scores are not calibrated probabilities on a real deployment population.
"""
    card_path = Path(model_card_output)
    card_path.parent.mkdir(parents=True, exist_ok=True)
    card_path.write_text(card, encoding="utf-8")
    return metrics
