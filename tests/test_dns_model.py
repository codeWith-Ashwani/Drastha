import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegisflow.dns_features import character_ngrams, lexical_features
from aegisflow.dns_model import DNSLabelledDomain, DNSNgramModel, read_dns_dataset, validate_leakage_safe_split


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

    def test_rejects_family_leakage(self):
        rows = [
            DNSLabelledDomain("bad-one.test", 1, "same-family", "train"),
            DNSLabelledDomain("bad-two.test", 1, "same-family", "test"),
        ]
        with self.assertRaisesRegex(ValueError, "family leakage"):
            validate_leakage_safe_split(rows)


if __name__ == "__main__":
    unittest.main()
