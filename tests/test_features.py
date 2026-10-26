"""Small boundary checks for the explainable detection rules."""

import unittest
from unittest.mock import patch

import pandas as pd

from detector import score_domains
import dns_feature_extractor
from dns_feature_extractor import aggregate_by_domain, shannon_entropy, split_domain


class FeatureTests(unittest.TestCase):
    def test_missing_tshark_is_actionable(self):
        with patch.object(dns_feature_extractor, "resolve_tshark_path", return_value=None):
            with self.assertRaisesRegex(FileNotFoundError, "TShark is unavailable"):
                dns_feature_extractor.parse_pcap("data/normal.pcap")

    def test_entropy_and_domain_split(self):
        self.assertEqual(shannon_entropy("aaaa"), 0)
        self.assertEqual(shannon_entropy("ab"), 1)
        self.assertEqual(split_domain("Chunk.Example.Attack."), ("chunk", "example.attack"))

    def test_aggregation_and_strict_rule_boundaries(self):
        queries = pd.DataFrame([
            {"query_name": "a.example.test", "query_len": 14, "subdomain_entropy": 0,
             "query_type": "TXT", "timestamp": "2026-01-01", "base_domain": "example.test"},
            {"query_name": "b.example.test", "query_len": 14, "subdomain_entropy": 0,
             "query_type": "A", "timestamp": "2026-01-01", "base_domain": "example.test"},
        ])
        summary = aggregate_by_domain(queries)
        self.assertEqual(summary.loc[0, "query_count"], 2)
        self.assertEqual(summary.loc[0, "txt_null_ratio"], 0.5)
        self.assertEqual(score_domains(summary).loc[0, "suspicion_score"], 1)

        boundary = pd.DataFrame([{"base_domain": "boundary.test", "avg_entropy": 3.5,
                                  "max_entropy": 4.5,
                                  "query_count": 20, "txt_null_ratio": 0.3, "avg_query_len": 50}])
        self.assertEqual(score_domains(boundary).loc[0, "suspicion_score"], 0)
        boundary.loc[0, "max_entropy"] = 4.51
        self.assertEqual(score_domains(boundary).loc[0, "suspicion_score"], 0)
        boundary.loc[0, "txt_null_ratio"] = 0.31
        self.assertEqual(score_domains(boundary).loc[0, "suspicion_score"], 2)
        boundary.loc[0, "txt_null_ratio"] = 0.3
        self.assertEqual(score_domains(boundary).loc[0, "suspicion_score"], 0)
        boundary.loc[0, "max_entropy"] = 4.5
        boundary.loc[0, "avg_entropy"] = 3.51
        boundary.loc[0, "query_count"] = 21
        self.assertEqual(score_domains(boundary).loc[0, "suspicion_score"], 2)


if __name__ == "__main__":
    unittest.main()
