from __future__ import annotations

import csv
import json
import math
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from aegisflow.dns_features import character_ngrams, normalized_domain


@dataclass(frozen=True, slots=True)
class DNSLabelledDomain:
    domain: str
    label: int
    family: str
    split: str


class DNSNgramModel:
    """Small, inspectable character n-gram Naive Bayes DGA classifier."""

    version = "1.0"

    def __init__(self, payload: dict) -> None:
        self.payload = payload

    @classmethod
    def train(cls, rows: Iterable[DNSLabelledDomain], ngram_size: int = 3) -> "DNSNgramModel":
        training = [row for row in rows if row.split == "train"]
        if not training or {row.label for row in training} != {0, 1}:
            raise ValueError("training split must contain both benign and malicious domains")
        counts = {0: Counter(), 1: Counter()}
        totals = {0: 0, 1: 0}
        documents = Counter(row.label for row in training)
        vocabulary: set[str] = set()
        for row in training:
            grams = character_ngrams(row.domain, ngram_size)
            counts[row.label].update(grams)
            totals[row.label] += len(grams)
            vocabulary.update(grams)
        return cls({
            "model_type": "character_ngram_multinomial_naive_bayes",
            "version": cls.version,
            "ngram_size": ngram_size,
            "alpha": 1.0,
            "documents": {str(key): value for key, value in documents.items()},
            "totals": {str(key): value for key, value in totals.items()},
            "counts": {
                str(label): dict(sorted(label_counts.items()))
                for label, label_counts in counts.items()
            },
            "vocabulary_size": len(vocabulary),
        })

    def predict_probability(self, domain: str) -> float:
        documents = self.payload["documents"]
        total_documents = sum(documents.values())
        vocabulary_size = max(int(self.payload["vocabulary_size"]), 1)
        alpha = float(self.payload.get("alpha", 1.0))
        scores: dict[int, float] = {}
        for label in (0, 1):
            label_key = str(label)
            prior = (documents[label_key] + alpha) / (total_documents + 2 * alpha)
            denominator = self.payload["totals"][label_key] + alpha * vocabulary_size
            score = math.log(prior)
            label_counts = self.payload["counts"][label_key]
            for gram in character_ngrams(normalized_domain(domain), int(self.payload["ngram_size"])):
                score += math.log((label_counts.get(gram, 0) + alpha) / denominator)
            scores[label] = score
        maximum = max(scores.values())
        benign = math.exp(scores[0] - maximum)
        malicious = math.exp(scores[1] - maximum)
        return malicious / (benign + malicious)

    def save(self, path: str | Path) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(self.payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "DNSNgramModel":
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))


def read_dns_dataset(path: str | Path) -> list[DNSLabelledDomain]:
    rows: list[DNSLabelledDomain] = []
    with Path(path).open("r", encoding="utf-8", newline="") as stream:
        for line_number, record in enumerate(csv.DictReader(stream), start=2):
            try:
                row = DNSLabelledDomain(
                    normalized_domain(record["domain"]),
                    int(record["label"]),
                    record["family"].strip().lower(),
                    record["split"].strip().lower(),
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(f"line {line_number}: invalid DNS dataset row: {exc}") from exc
            if row.label not in (0, 1) or row.split not in ("train", "test"):
                raise ValueError(f"line {line_number}: label must be 0/1 and split train/test")
            rows.append(row)
    validate_leakage_safe_split(rows)
    return rows


def validate_leakage_safe_split(rows: Iterable[DNSLabelledDomain]) -> None:
    rows = list(rows)
    splits_by_domain: dict[str, set[str]] = {}
    for row in rows:
        splits_by_domain.setdefault(row.domain, set()).add(row.split)
    leaked_domains = sorted(domain for domain, splits in splits_by_domain.items() if len(splits) > 1)
    if leaked_domains:
        raise ValueError(f"domain leakage across splits: {', '.join(leaked_domains[:3])}")
    malicious_families = {
        split: {row.family for row in rows if row.label == 1 and row.split == split}
        for split in ("train", "test")
    }
    leaked_families = malicious_families["train"] & malicious_families["test"]
    if leaked_families:
        raise ValueError(f"malware-family leakage across splits: {', '.join(sorted(leaked_families))}")


def evaluate_dns_model(model: DNSNgramModel, rows: Iterable[DNSLabelledDomain], threshold: float = 0.5) -> dict:
    test_rows = [row for row in rows if row.split == "test"]
    if not test_rows:
        raise ValueError("dataset requires a test split")
    tp = fp = tn = fn = 0
    examples = []
    for row in test_rows:
        probability = model.predict_probability(row.domain)
        prediction = int(probability >= threshold)
        tp += int(row.label == 1 and prediction == 1)
        fp += int(row.label == 0 and prediction == 1)
        tn += int(row.label == 0 and prediction == 0)
        fn += int(row.label == 1 and prediction == 0)
        examples.append({"domain": row.domain, "label": row.label, "probability": round(probability, 6)})
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "test_examples": len(test_rows),
        "threshold": threshold,
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "accuracy": round((tp + tn) / len(test_rows), 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0.0,
        "examples": examples,
    }
