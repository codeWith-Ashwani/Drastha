from __future__ import annotations

import csv
import json
import math
from collections import Counter
from dataclasses import dataclass
from hashlib import blake2b
from pathlib import Path
from typing import Iterable

from aegisflow.dns_features import character_ngrams, lexical_features, normalized_domain


@dataclass(frozen=True, slots=True)
class DNSLabelledDomain:
    domain: str
    label: int
    family: str
    split: str


class DNSNgramModel:
    """Small, inspectable character n-gram Naive Bayes DGA classifier."""

    version = "1.1"

    def __init__(self, payload: dict) -> None:
        self.payload = payload

    @classmethod
    def train(cls, rows: Iterable[DNSLabelledDomain], ngram_size: int = 3,
              count_mode: str = "frequency") -> "DNSNgramModel":
        rows = list(rows)
        validate_leakage_safe_split(rows)
        training = [row for row in rows if row.split == "train"]
        if not training or {row.label for row in training} != {0, 1}:
            raise ValueError("training split must contain both benign and malicious domains")
        if count_mode not in {"frequency", "binary_presence"}:
            raise ValueError("Unsupported DNS n-gram count mode")
        counts = {0: Counter(), 1: Counter()}
        totals = {0: 0, 1: 0}
        documents = Counter(row.label for row in training)
        vocabulary: set[str] = set()
        feature_names = tuple(sorted(lexical_features("example.test")))
        lexical_values = {0: {name: [] for name in feature_names},
                          1: {name: [] for name in feature_names}}
        for row in training:
            grams = character_ngrams(row.domain, ngram_size)
            if count_mode == "binary_presence":
                grams = sorted(set(grams))
            counts[row.label].update(grams)
            totals[row.label] += len(grams)
            vocabulary.update(grams)
            features = lexical_features(row.domain)
            for name in feature_names:
                lexical_values[row.label][name].append(features[name])
        lexical_stats = {}
        for label in (0, 1):
            lexical_stats[str(label)] = {}
            for name in feature_names:
                values = lexical_values[label][name]
                mean = sum(values) / len(values)
                variance = sum((value - mean) ** 2 for value in values) / len(values)
                lexical_stats[str(label)][name] = {
                    "mean": mean,
                    "variance": max(variance, 1e-6),
                }
        return cls({
            "model_type": "character_ngram_multinomial_naive_bayes",
            "version": cls.version,
            "ngram_size": ngram_size,
            "count_mode": count_mode,
            "alpha": 1.0,
            "documents": {str(key): value for key, value in documents.items()},
            "totals": {str(key): value for key, value in totals.items()},
            "counts": {
                str(label): dict(sorted(label_counts.items()))
                for label, label_counts in counts.items()
            },
            "vocabulary_size": len(vocabulary),
            "lexical_stats": lexical_stats,
            "ngram_weight": 1.0,
            "lexical_weight": 0.0,
        })

    def predict_probability(self, domain: str) -> float:
        documents = self.payload["documents"]
        total_documents = sum(documents.values())
        vocabulary_size = max(int(self.payload["vocabulary_size"]), 1)
        alpha = float(self.payload.get("alpha", 1.0))
        scores: dict[int, float] = {}
        grams = character_ngrams(normalized_domain(domain), int(self.payload["ngram_size"]))
        count_mode = self.payload.get("count_mode", "frequency")
        if count_mode == "binary_presence":
            grams = sorted(set(grams))
        elif count_mode != "frequency":
            raise ValueError("Unsupported DNS model count mode")
        score_mode = self.payload.get("score_mode", "multinomial")
        if score_mode not in {"multinomial", "mean_log_likelihood"}:
            raise ValueError("Unsupported DNS model score mode")
        for label in (0, 1):
            label_key = str(label)
            prior = (documents[label_key] + alpha) / (total_documents + 2 * alpha)
            denominator = self.payload["totals"][label_key] + alpha * vocabulary_size
            score = math.log(prior)
            label_counts = self.payload["counts"][label_key]
            likelihood = sum(math.log((label_counts.get(gram, 0) + alpha) / denominator)
                             for gram in grams)
            score += likelihood / max(len(grams), 1) if score_mode == "mean_log_likelihood" else likelihood
            scores[label] = score
        ngram_log_odds = scores[1] - scores[0]
        lexical_log_odds = 0.0
        lexical_weight = float(self.payload.get("lexical_weight", 0.0))
        if lexical_weight:
            statistics = self.payload.get("lexical_stats")
            if not isinstance(statistics, dict) or set(statistics) != {"0", "1"}:
                raise ValueError("Hybrid DNS model requires lexical class statistics")
            features = lexical_features(domain)
            lexical_scores = {}
            for label in (0, 1):
                lexical_scores[label] = 0.0
                for name, value in features.items():
                    descriptor = statistics[str(label)].get(name)
                    if not isinstance(descriptor, dict):
                        raise ValueError(f"Hybrid DNS model is missing lexical feature: {name}")
                    variance = max(float(descriptor["variance"]), 1e-6)
                    difference = value - float(descriptor["mean"])
                    lexical_scores[label] += -0.5 * (math.log(variance) + difference * difference / variance)
            lexical_log_odds = lexical_scores[1] - lexical_scores[0]
        combined = float(self.payload.get("ngram_weight", 1.0)) * ngram_log_odds + lexical_weight * lexical_log_odds
        scores = {0: 0.0, 1: max(-700.0, min(700.0, combined))}
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
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if payload.get("schema_version") == "drastha-dns-candidate-v1" or payload.get("research_status"):
            raise ValueError("Research DNS candidate is not approved for deployment; use evaluate-dns-candidate")
        if payload.get("model_type") == "hashed_character_logistic_regression":
            return DNSHashedLogisticModel(payload)
        return cls(payload)


class DNSHashedLogisticModel(DNSNgramModel):
    """Deterministic sparse logistic DGA model with bounded feature hashing."""

    version = "1.0"
    FEATURE_NAMES = tuple(sorted(lexical_features("example.test")))

    @staticmethod
    def _token_coordinate(token: str, dimensions: int) -> tuple[int, float]:
        value = blake2b(token.encode("utf-8"), digest_size=8,
                        person=b"drastha").digest()
        return int.from_bytes(value[:4], "big") % dimensions, 1.0 if value[4] & 1 else -1.0

    @classmethod
    def _vector(cls, domain: str, payload: dict) -> dict[int, float]:
        dimensions = int(payload["hash_dimensions"])
        counts: Counter[int] = Counter()
        for size in payload["ngram_sizes"]:
            for token in character_ngrams(domain, int(size)):
                index, sign = cls._token_coordinate(f"{size}:{token}", dimensions)
                counts[index] += sign
        norm = math.sqrt(sum(value * value for value in counts.values())) or 1.0
        vector = {index: value / norm for index, value in counts.items() if value}
        features = lexical_features(domain)
        for offset, name in enumerate(cls.FEATURE_NAMES):
            descriptor = payload["lexical_scaler"][name]
            value = (features[name] - descriptor["mean"]) / descriptor["scale"]
            vector[dimensions + offset] = max(-5.0, min(5.0, value)) / 5.0
        return vector

    @staticmethod
    def _sigmoid(value: float) -> float:
        value = max(-40.0, min(40.0, value))
        return 1.0 / (1.0 + math.exp(-value))

    @classmethod
    def train(cls, rows: Iterable[DNSLabelledDomain], *, hash_dimensions: int = 4096,
              ngram_sizes: tuple[int, ...] = (2, 3, 4), epochs: int = 4,
              learning_rate: float = 0.08, l2: float = 0.0001) -> "DNSHashedLogisticModel":
        training = [row for row in rows if row.split == "train"]
        if not training or {row.label for row in training} != {0, 1}:
            raise ValueError("training split must contain both benign and malicious domains")
        if (type(hash_dimensions) is not int or not 256 <= hash_dimensions <= 65536
                or not ngram_sizes or any(type(size) is not int or not 2 <= size <= 5 for size in ngram_sizes)
                or tuple(sorted(set(ngram_sizes))) != tuple(ngram_sizes)
                or type(epochs) is not int or not 1 <= epochs <= 20
                or not 0 < learning_rate <= 1 or not 0 <= l2 <= 0.1):
            raise ValueError("Invalid hashed logistic DNS model configuration")
        observed = {name: [] for name in cls.FEATURE_NAMES}
        for row in training:
            values = lexical_features(row.domain)
            for name in cls.FEATURE_NAMES:
                observed[name].append(values[name])
        scaler = {}
        for name, values in observed.items():
            mean = sum(values) / len(values)
            variance = sum((value - mean) ** 2 for value in values) / len(values)
            scaler[name] = {"mean": mean, "scale": max(math.sqrt(variance), 1e-6)}
        payload = {
            "model_type": "hashed_character_logistic_regression", "version": cls.version,
            "hash_algorithm": "blake2b-64-signed-v1", "hash_dimensions": hash_dimensions,
            "ngram_sizes": list(ngram_sizes), "epochs": epochs,
            "learning_rate": learning_rate, "l2": l2, "lexical_scaler": scaler,
            "research_status": "not_approved",
        }
        family_counts = Counter((row.label, row.family) for row in training)
        family_totals = Counter({label: len({family for item_label, family in family_counts
                                             if item_label == label}) for label in (0, 1)})
        row_count = len(training)
        weights = [0.0] * (hash_dimensions + len(cls.FEATURE_NAMES))
        bias = 0.0
        vectors = {normalized_domain(row.domain): cls._vector(row.domain, payload)
                   for row in training}
        for epoch in range(epochs):
            ordered = sorted(training, key=lambda row: blake2b(
                f"{epoch}|{normalized_domain(row.domain)}".encode(), digest_size=8,
                person=b"dns-order").digest())
            rate = learning_rate / math.sqrt(epoch + 1)
            for row in ordered:
                vector = vectors[normalized_domain(row.domain)]
                probability = cls._sigmoid(bias + sum(weights[index] * value
                                                       for index, value in vector.items()))
                balance = row_count / (2 * family_totals[row.label]
                                       * family_counts[(row.label, row.family)])
                error = max(-10.0, min(10.0, (probability - row.label) * balance))
                bias -= rate * error
                for index, value in vector.items():
                    weights[index] -= rate * (error * value + l2 * weights[index])
        payload.update(weights=weights, bias=bias,
                       balancing="equal-class-and-equal-family-contribution-v1",
                       training_records=row_count,
                       training_families={str(label): family_totals[label] for label in (0, 1)})
        return cls(payload)

    def predict_probability(self, domain: str) -> float:
        vector = self._vector(domain, self.payload)
        weights = self.payload["weights"]
        if len(weights) != int(self.payload["hash_dimensions"]) + len(self.FEATURE_NAMES):
            raise ValueError("Hashed logistic DNS model weight dimensions are invalid")
        return self._sigmoid(float(self.payload["bias"]) + sum(
            float(weights[index]) * value for index, value in vector.items()))


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
            if row.label not in (0, 1) or row.split not in ("train", "validation", "test"):
                raise ValueError(f"line {line_number}: label must be 0/1 and split train/validation/test")
            rows.append(row)
    validate_leakage_safe_split(rows)
    return rows


def validate_leakage_safe_split(rows: Iterable[DNSLabelledDomain]) -> None:
    rows = list(rows)
    splits_by_domain: dict[str, set[str]] = {}
    seen = set()
    for row in rows:
        domain = normalized_domain(row.domain)
        if not domain or row.label not in (0, 1) or row.split not in {"train", "validation", "test"} or not row.family.strip():
            raise ValueError("Invalid DNS label, family, split or empty domain")
        if (domain, row.split) in seen:
            raise ValueError("duplicate domain within split (including conflicting labels)")
        seen.add((domain, row.split))
        splits_by_domain.setdefault(domain, set()).add(row.split)
    leaked_domains = sorted(domain for domain, splits in splits_by_domain.items() if len(splits) > 1)
    if leaked_domains:
        raise ValueError(f"domain leakage across splits: {', '.join(leaked_domains[:3])}")
    malicious_families = {
        split: {row.family.strip().lower() for row in rows if row.label == 1 and row.split == split}
        for split in ("train", "validation", "test")
    }
    leaked_families = set().union(*(malicious_families[a] & malicious_families[b]
                                   for a, b in (("train", "validation"), ("train", "test"), ("validation", "test"))))
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
