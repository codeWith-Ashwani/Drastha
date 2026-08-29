from __future__ import annotations

import math
from collections import Counter


def normalized_domain(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def base_domain(domain: str) -> str:
    labels = [label for label in normalized_domain(domain).split(".") if label]
    return ".".join(labels[-2:]) if len(labels) >= 2 else ".".join(labels)


def leftmost_label(domain: str) -> str:
    return normalized_domain(domain).split(".", 1)[0]


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def character_ngrams(domain: str, size: int = 3) -> tuple[str, ...]:
    value = f"^{normalized_domain(domain)}$"
    if len(value) < size:
        return (value,)
    return tuple(value[index:index + size] for index in range(len(value) - size + 1))


def lexical_features(domain: str) -> dict[str, float]:
    value = normalized_domain(domain)
    compact = value.replace(".", "")
    labels = [label for label in value.split(".") if label]
    length = max(len(compact), 1)
    digits = sum(character.isdigit() for character in compact)
    hyphens = compact.count("-")
    vowels = sum(character in "aeiou" for character in compact)
    return {
        "domain_length": float(len(value)),
        "label_count": float(len(labels)),
        "max_label_length": float(max((len(label) for label in labels), default=0)),
        "digit_ratio": digits / length,
        "hyphen_ratio": hyphens / length,
        "vowel_ratio": vowels / length,
        "unique_character_ratio": len(set(compact)) / length,
        "entropy": shannon_entropy(compact),
    }
