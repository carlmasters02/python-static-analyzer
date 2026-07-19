"""Tests for Milestone 6: the benchmark scorer.

These pin the expected confusion-matrix numbers so an accidental change to
the engine that silently helps or hurts the score is caught.
"""

import unittest

from benchmark.score import score


class TestBenchmarkDefault(unittest.TestCase):
    def test_default_mode_confusion_matrix(self):
        counts, _ = score(assume_tainted_params=True)
        self.assertEqual(counts.tp, 9)
        self.assertEqual(counts.fp, 1)   # the flow-insensitive reassignment case
        self.assertEqual(counts.fn, 3)   # the three known-limitation cases
        self.assertEqual(counts.tn, 9)

    def test_default_metrics(self):
        counts, _ = score(assume_tainted_params=True)
        self.assertAlmostEqual(counts.precision(), 0.90, places=2)
        self.assertAlmostEqual(counts.recall(), 0.75, places=2)


class TestBenchmarkNoParams(unittest.TestCase):
    def test_no_params_lowers_recall(self):
        default, _ = score(assume_tainted_params=True)
        no_params, _ = score(assume_tainted_params=False)
        # Turning off param-tainting trades recall for (slightly) precision.
        self.assertLess(no_params.recall(), default.recall())


if __name__ == "__main__":
    unittest.main()
