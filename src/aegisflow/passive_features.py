"""Causal, metadata-only sequence features. No labels or decrypted content."""
from __future__ import annotations

import math
from collections import Counter, OrderedDict, deque
from dataclasses import asdict, dataclass, replace
from hashlib import sha256
import json
from statistics import median

from aegisflow.models import EncryptedSessionMetadata


@dataclass(frozen=True)
class PassiveFeatureConfig:
    history_seconds: float = 3600
    minimum_baseline_sessions: int = 20
    minimum_prevalence_sessions: int = 100
    maximum_history: int = 5000
    maximum_cohorts: int = 128
    sequence_length: int = 8
    minimum_packets: int = 4
    size_scale_floor: float = 32
    timing_scale_floor: float = 0.001
    anomaly_scale: float = 6
    learning_ceiling: float = 0.75

    def __post_init__(self):
        if not (2 <= self.minimum_packets <= self.sequence_length <= 128):
            raise ValueError("Invalid sequence length/minimum packets")
        if min(self.minimum_baseline_sessions, self.minimum_prevalence_sessions) < 2:
            raise ValueError("At least two history sessions required")
        if self.maximum_history < max(self.minimum_baseline_sessions, self.minimum_prevalence_sessions):
            raise ValueError("History limit cannot be smaller than warm-up")
        if self.maximum_cohorts < 1 or any(not math.isfinite(x) or x <= 0 for x in
                (self.history_seconds, self.size_scale_floor, self.timing_scale_floor, self.anomaly_scale)):
            raise ValueError("Feature bounds must be finite and positive")
        if not 0 < self.learning_ceiling <= 1:
            raise ValueError("Invalid baseline learning ceiling")


def sequence_vectors(event, config):
    observations = event.raw.get("packet_observations")
    if not isinstance(observations, list) or not observations:
        return None, "packet_sequence_missing"
    if len(observations) > 128:
        return None, "packet_sequence_over_limit"
    sizes, times = [], []
    for packet in observations:
        try:
            if not isinstance(packet, dict) or isinstance(packet["ts"], bool) or isinstance(packet["ip_bytes"], bool):
                raise ValueError()
            timestamp, size = float(packet["ts"]), float(packet["ip_bytes"])
            direction = packet["direction"]
            if not math.isfinite(timestamp) or not math.isfinite(size) or not 0 < size <= 65575:
                raise ValueError()
            if size != int(size) or direction not in {"orig", "resp"}:
                raise ValueError()
            if timestamp > event.timestamp or (times and timestamp < times[-1]):
                return None, "packet_sequence_time_invalid"
            sizes.append(size if direction == "orig" else -size)
            times.append(timestamp)
        except (KeyError, TypeError, ValueError, OverflowError):
            return None, "packet_sequence_invalid"
    if len(sizes) < config.minimum_packets:
        return None, "packet_sequence_too_short"
    count = min(len(sizes), config.sequence_length)
    return (tuple(sizes[:count]), tuple(b - a for a, b in zip(times[:count], times[1:count]))), None


class PassiveFeatureExtractor:
    version = "packet-sequence-robust-v1"

    def __init__(self, config=None):
        self.config = config or PassiveFeatureConfig()
        self._cohorts = OrderedDict()
        self.counts = Counter()

    def _score(self, vector, histories, dimension, floor):
        deviations = []
        for position, value in enumerate(vector):
            reference = [item[2][dimension][position] for item in histories if len(item[2][dimension]) > position]
            if len(reference) < self.config.minimum_baseline_sessions:
                return None
            center = median(reference)
            mad = median(abs(x - center) for x in reference)
            scale = max(1.4826 * mad, floor)
            deviations.append(abs(value - center) / scale)
        return round(min(1.0, median(deviations) / self.config.anomaly_scale), 6)

    def enrich(self, event: EncryptedSessionMetadata, *, allow_supplied=False):
        self.counts["observations"] += 1
        # Cohorts do NOT include fingerprint or destination IP: new identities must
        # still be comparable to prior traffic for the same service/sensor.
        fingerprint_kind = "ja4" if event.raw.get("ja4") else "ja3" if (
            event.raw.get("ja3") or event.raw.get("observed_ja3") == event.client_fingerprint
        ) else "unspecified"
        cohort = (str(event.raw.get("sensor_id", "default")), event.transport,
                  str(event.raw.get("id.resp_p", 443)), event.application_protocol, fingerprint_kind)
        if cohort not in self._cohorts:
            if len(self._cohorts) >= self.config.maximum_cohorts:
                self._cohorts.popitem(last=False)
                self.counts["cohorts_evicted"] += 1
            self._cohorts[cohort] = deque(maxlen=self.config.maximum_history)
        self._cohorts.move_to_end(cohort)
        history = self._cohorts[cohort]
        cutoff = event.timestamp - self.config.history_seconds
        while history and history[0][0] < cutoff:
            history.popleft()
        # Same flow metadata cannot inflate fingerprint counts or warm-up samples.
        identity = (event.flow_id, event.src_ip, event.dst_ip)
        duplicate = any(item[3] == identity for item in history)
        fingerprint = event.client_fingerprint
        prior = [item for item in history if item[1]]
        prevalence = (sum(item[1] == fingerprint for item in prior) / len(prior)
                      if fingerprint and len(prior) >= self.config.minimum_prevalence_sessions else None)
        vectors, reason = sequence_vectors(event, self.config)
        baselines = [item for item in history if item[2] is not None]
        size_score = timing_score = None
        if vectors is not None and len(baselines) >= self.config.minimum_baseline_sessions:
            size_score = self._score(vectors[0], baselines, 0, self.config.size_scale_floor)
            timing_score = self._score(vectors[1], baselines, 1, self.config.timing_scale_floor)
        available = all(value is not None for value in (prevalence, size_score, timing_score)) and not duplicate
        statuses = []
        if reason:
            statuses.append(reason)
        if not fingerprint:
            statuses.append("fingerprint_missing")
        if prevalence is None:
            statuses.append("prevalence_warmup")
        if size_score is None or timing_score is None:
            statuses.append("sequence_baseline_warmup" if vectors is not None else "sequence_unavailable")
        if duplicate:
            statuses.append("duplicate_session")

        metadata = {"extractor_version": self.version, "status": "derived" if available else "insufficient_evidence",
                    "reasons": statuses, "baseline_sessions": len(baselines), "prevalence_sessions": len(prior),
                    "baseline_scope": list(cohort), "history_seconds": self.config.history_seconds,
                    "flow_id": event.flow_id, "observation_time": event.timestamp,
                    "capture_provenance": event.raw.get("capture_provenance"),
                    "sequence_sha256": sha256(json.dumps(event.raw.get("packet_observations"), sort_keys=True).encode()).hexdigest()}
        raw = dict(event.raw)
        supplied = raw.get("features", raw.get("ml_evidence", raw.get("evidence", {})))
        supplied_complete = isinstance(supplied, dict) and all(
            name in supplied for name in ("packet_size_sequence_anomaly", "timing_sequence_anomaly")
        ) and any(name in supplied for name in ("ja3_prevalence", "ja4_prevalence", "fingerprint_prevalence"))
        supplied_valid = False
        if supplied_complete:
            try:
                prevalence_value = supplied.get("fingerprint_prevalence", supplied.get("ja4_prevalence", supplied.get("ja3_prevalence")))
                supplied_valid = bool(fingerprint) and all(math.isfinite(float(value)) and 0 <= float(value) <= 1
                    for value in (prevalence_value, supplied["packet_size_sequence_anomaly"], supplied["timing_sequence_anomaly"]))
            except (TypeError, ValueError, OverflowError):
                pass
            if not supplied_valid and allow_supplied:
                statuses.append("supplied_features_invalid")
        if available:
            raw["features"] = {"fingerprint_prevalence": prevalence,
                               "packet_size_sequence_anomaly": size_score,
                               "timing_sequence_anomaly": timing_score}
            self.counts["derived"] += 1
        elif allow_supplied and supplied_valid and "packet_observations" not in raw and not duplicate:
            # Explicit compatibility mode only; never described as measured data.
            metadata["status"] = "supplied_compatibility"
            self.counts["supplied_compatibility"] += 1
        else:
            raw["features"] = {}  # overrides aliases; missing is not a zero anomaly.
            self.counts["insufficient_evidence"] += 1
        for status in statuses:
            self.counts[status] += 1
        raw["feature_provenance"] = metadata
        # Learn only after scoring, and exclude suspicious sequences from baseline.
        safe_to_learn = (size_score is None or timing_score is None or
                         max(size_score, timing_score) < self.config.learning_ceiling)
        learned = vectors if vectors and safe_to_learn else None
        # Do not let a sequence already measured as anomalous make its own
        # fingerprint look prevalent to later events in the same attack burst.
        # This fixes causal baseline contamination; it does not change a detector
        # threshold or assume the event is malicious.
        if not duplicate and safe_to_learn:
            history.append((event.timestamp, fingerprint, learned, identity))
        elif not duplicate:
            self.counts["anomalous_sessions_excluded_from_baseline"] += 1
        return replace(event, raw=raw)

    def summary(self):
        return {"extractor_version": self.version, "counts": dict(self.counts),
                "active_cohorts": len(self._cohorts), "configuration": asdict(self.config)}
