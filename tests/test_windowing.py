import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegisflow.windowing import KeyedSlidingWindow


class SlidingWindowTests(unittest.TestCase):
    def test_expires_old_values(self):
        window = KeyedSlidingWindow[str, str](2.0)
        window.add("host", 0.0, "a")
        window.add("host", 1.0, "b")
        values = window.add("host", 3.1, "c")
        self.assertEqual([item.value for item in values], ["c"])

    def test_keeps_late_value_when_it_is_still_inside_window(self):
        window = KeyedSlidingWindow[str, str](5.0)
        window.add("host", 10.0, "new")
        values = window.add("host", 8.0, "late")
        self.assertEqual([item.value for item in values], ["late", "new"])


if __name__ == "__main__":
    unittest.main()

