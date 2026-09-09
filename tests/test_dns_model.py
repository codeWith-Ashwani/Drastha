import sys
import unittest
from copy import deepcopy
import json
import math
from pathlib import Path
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegisflow.dns_features import character_ngrams, lexical_features
from aegisflow.dns_model import (DNSHashedLogisticModel, DNSLabelledDomain,
                                 DNSNgramModel, read_dns_dataset,
                                 validate_leakage_safe_split)


class DNSModelTests(unittest.TestCase):
    def test_features_include_lexical_and_ngrams(self):
        features = lexical_features("a8x9-example.test")
        self.assertGreater(features["entropy"], 0)
        self.assertGreater(features["digit_ratio"], 0)
        self.assertIn("^a8", character_ngrams("a8x.test"))

    def test_fixture_split_is_leakage_safe_and_model_scores(self):
        dataset = Path(__file__).resolve().parents[1] / "examples" / "dns_training_demo.csv"
        rows = read_dns_dataset(dataset)
        model = DNSNgramModel.train(rows)
        probability = model.predict_probability("v8m2q6z9x4c7n1k5.biz")
        self.assertGreaterEqual(probability, 0.0)
        self.assertLessEqual(probability, 1.0)

    def test_hybrid_lexical_scoring_is_finite_and_old_payload_is_compatible(self):
        dataset = Path(__file__).resolve().parents[1] / "examples" / "dns_training_demo.csv"
        model = DNSNgramModel.train(read_dns_dataset(dataset))
        domain = "v8m2q6z9x4c7n1k5.biz"
        ngram_only = model.predict_probability(domain)
        legacy_payload = deepcopy(model.payload)
        for key in ("lexical_stats", "ngram_weight", "lexical_weight"):
            legacy_payload.pop(key)
        self.assertAlmostEqual(ngram_only, DNSNgramModel(legacy_payload).predict_probability(domain), places=12)
        hybrid_payload = deepcopy(model.payload)
        hybrid_payload.update(ngram_weight=0.75, lexical_weight=0.25)
        hybrid_score = DNSNgramModel(hybrid_payload).predict_probability(domain)
        self.assertTrue(math.isfinite(hybrid_score))
        self.assertNotAlmostEqual(ngram_only, hybrid_score, places=8)

    def test_rejects_family_leakage(self):
        rows = [
            DNSLabelledDomain("bad-one.test", 1, "same-family", "train"),
            DNSLabelledDomain("bad-two.test", 1, "same-family", "test"),
        ]
        with self.assertRaisesRegex(ValueError, "family leakage"):
            validate_leakage_safe_split(rows)

    def test_hashed_logistic_model_is_deterministic_bounded_and_research_only(self):
        rows = []
        for index in range(30):
            rows.append(DNSLabelledDomain(f"service-{index}.example.test", 0,
                                           "benign", "train"))
            rows.append(DNSLabelledDomain(f"x9q{index:03d}z8k7v6m5.biz", 1,
                                           "dga", "train"))
        settings = dict(hash_dimensions=256, ngram_sizes=(2, 3), epochs=2,
                        learning_rate=0.08, l2=0.0001)
        first = DNSHashedLogisticModel.train(rows, **settings)
        second = DNSHashedLogisticModel.train(rows, **settings)
        self.assertEqual(first.payload, second.payload)
        benign = first.predict_probability("service-99.example.test")
        malicious = first.predict_probability("x9q999z8k7v6m5.biz")
        self.assertTrue(0 <= benign <= 1 and 0 <= malicious <= 1)
        self.assertGreater(malicious, benign)
        index, sign = DNSHashedLogisticModel._token_coordinate("3:^abc", 256)
        self.assertTrue(0 <= index < 256)
        self.assertIn(sign, {-1.0, 1.0})

    def test_hashed_logistic_model_rejects_invalid_configuration_and_runtime_loading(self):
        rows = [DNSLabelledDomain("normal.example", 0, "benign", "train"),
                DNSLabelledDomain("x9q8z7.biz", 1, "dga", "train")]
        with self.assertRaisesRegex(ValueError, "Invalid hashed logistic"):
            DNSHashedLogisticModel.train(rows, hash_dimensions=10)
        model = DNSHashedLogisticModel.train(rows, hash_dimensions=256, epochs=1)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "model.json"
            model.save(path)
            with self.assertRaisesRegex(ValueError, "not approved"):
                DNSNgramModel.load(path)
            approved = deepcopy(model.payload)
            approved.pop("research_status")
            path.write_text(json.dumps(approved), encoding="utf-8")
            loaded = DNSNgramModel.load(path)
            self.assertIsInstance(loaded, DNSHashedLogisticModel)
            self.assertAlmostEqual(model.predict_probability("x9q8z7.biz"),
                                   loaded.predict_probability("x9q8z7.biz"))


if __name__ == "__main__":
    unittest.main()
