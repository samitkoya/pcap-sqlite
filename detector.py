"""Apply four explainable DNS tunneling rules to extracted domain summaries."""

import argparse
import sqlite3
from contextlib import closing
from pathlib import Path

import pandas as pd


ENTROPY_THRESHOLD = 3.5
MAX_ENTROPY_THRESHOLD = 4.5
QUERY_COUNT_THRESHOLD = 20
TXT_NULL_RATIO_THRESHOLD = 0.3
QUERY_LENGTH_THRESHOLD = 50
FLAG_SCORE_THRESHOLD = 2

REQUIRED_COLUMNS = {
    "base_domain", "avg_entropy", "max_entropy", "query_count", "txt_null_ratio", "avg_query_len"
}


def entropy_rule_hit(agg_df: pd.DataFrame) -> pd.Series:
    """Catch sustained randomness or a high peak paired with TXT/NULL use."""
    return ((agg_df["avg_entropy"] > ENTROPY_THRESHOLD)
            | ((agg_df["max_entropy"] > MAX_ENTROPY_THRESHOLD)
               & (agg_df["txt_null_ratio"] > TXT_NULL_RATIO_THRESHOLD)))


def score_domains(agg_df: pd.DataFrame) -> pd.DataFrame:
    """Give one point per signal and flag scores of at least two.

    Encoded tunnel labels can raise entropy and name length. Repeated queries
    can indicate data transfer, while TXT/NULL requests can carry payloads.
    Each signal can also occur in ordinary DNS, so a flag calls for review.
    """
    missing = REQUIRED_COLUMNS - set(agg_df.columns)
    if missing:
        raise ValueError(f"Missing domain summary columns: {', '.join(sorted(missing))}")

    results = agg_df.copy()
    results["suspicion_score"] = (
        entropy_rule_hit(results).astype(int)
        + (results["query_count"] > QUERY_COUNT_THRESHOLD).astype(int)
        + (results["txt_null_ratio"] > TXT_NULL_RATIO_THRESHOLD).astype(int)
        + (results["avg_query_len"] > QUERY_LENGTH_THRESHOLD).astype(int)
    )
    results["flagged"] = results["suspicion_score"] >= FLAG_SCORE_THRESHOLD
    return results


def evaluate(flagged_results: pd.DataFrame, known_malicious_domains: list[str],
             known_benign_domains: list[str] | None = None) -> None:
    """Count only independently supplied labels; keep other flags unverified."""
    labels = {domain.lower().rstrip(".") for domain in known_malicious_domains}
    benign = {domain.lower().rstrip(".") for domain in (known_benign_domains or [])}
    if labels & benign:
        raise ValueError("A domain cannot be both known malicious and known benign")
    flagged = flagged_results.loc[flagged_results["flagged"], "base_domain"]
    flagged_names = {str(domain).lower().rstrip(".") for domain in flagged}
    true_positives = len(flagged_names & labels)
    false_positives = len(flagged_names & benign)
    unverified = len(flagged_names - labels - benign)
    print(f"True positives: {true_positives}")
    print(f"False positives (independently labeled benign): {false_positives}")
    print(f"Unverified flagged domains: {unverified}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True, help="SQLite database created by dns_feature_extractor.py")
    parser.add_argument("--known-malicious", action="append", default=[], metavar="DOMAIN",
                        help="Known malicious base domain; repeat for multiple labels")
    parser.add_argument("--known-benign", action="append", default=[], metavar="DOMAIN",
                        help="Independently known benign base domain; repeat for multiple labels")
    args = parser.parse_args()

    db_path = Path(args.db)
    if not db_path.is_file():
        parser.error(f"Database does not exist: {db_path}")
    with closing(sqlite3.connect(f"{db_path.resolve().as_uri()}?mode=ro", uri=True)) as connection:
        summary = pd.read_sql_query("SELECT * FROM domain_summary", connection)
    results = score_domains(summary)
    results = results.sort_values(["suspicion_score", "query_count", "base_domain"],
                                  ascending=[False, False, True])
    for row in results.itertuples(index=False):
        status = "FLAGGED" if row.flagged else "clear"
        print(f"{row.base_domain}: score {row.suspicion_score}/4, {status}")
    print(f"Flagged domains: {int(results['flagged'].sum())} of {len(results)}")
    if args.known_malicious or args.known_benign:
        evaluate(results, args.known_malicious, args.known_benign)


if __name__ == "__main__":
    main()
