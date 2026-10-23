"""Apply four explainable DNS tunneling rules to extracted domain summaries."""

import argparse
import sqlite3
from pathlib import Path

import pandas as pd


ENTROPY_THRESHOLD = 3.5
QUERY_COUNT_THRESHOLD = 20
TXT_NULL_RATIO_THRESHOLD = 0.3
QUERY_LENGTH_THRESHOLD = 50
FLAG_SCORE_THRESHOLD = 2

REQUIRED_COLUMNS = {
    "base_domain", "avg_entropy", "query_count", "txt_null_ratio", "avg_query_len"
}


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
        (results["avg_entropy"] > ENTROPY_THRESHOLD).astype(int)
        + (results["query_count"] > QUERY_COUNT_THRESHOLD).astype(int)
        + (results["txt_null_ratio"] > TXT_NULL_RATIO_THRESHOLD).astype(int)
        + (results["avg_query_len"] > QUERY_LENGTH_THRESHOLD).astype(int)
    )
    results["flagged"] = results["suspicion_score"] >= FLAG_SCORE_THRESHOLD
    return results


def evaluate(flagged_results: pd.DataFrame, known_malicious_domains: list[str]) -> None:
    """Print positive counts against supplied labels; absent labels are assumed negative.

    A false-positive count is meaningful only if all other domains have been
    independently checked as non-malicious. Detector output is not a label.
    """
    labels = {domain.lower().rstrip(".") for domain in known_malicious_domains}
    flagged = flagged_results.loc[flagged_results["flagged"], "base_domain"]
    flagged_names = {str(domain).lower().rstrip(".") for domain in flagged}
    true_positives = len(flagged_names & labels)
    false_positives = len(flagged_names - labels)
    print(f"True positives: {true_positives}")
    print(f"False positives (assuming unlisted domains are negative): {false_positives}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True, help="SQLite database created by dns_feature_extractor.py")
    parser.add_argument("--known-malicious", action="append", default=[], metavar="DOMAIN",
                        help="Known malicious base domain; repeat for multiple labels")
    args = parser.parse_args()

    db_path = Path(args.db)
    if not db_path.is_file():
        parser.error(f"Database does not exist: {db_path}")
    with sqlite3.connect(f"{db_path.resolve().as_uri()}?mode=ro", uri=True) as connection:
        summary = pd.read_sql_query("SELECT * FROM domain_summary", connection)
    results = score_domains(summary)
    results = results.sort_values(["suspicion_score", "query_count", "base_domain"],
                                  ascending=[False, False, True])
    for row in results.itertuples(index=False):
        status = "FLAGGED" if row.flagged else "clear"
        print(f"{row.base_domain}: score {row.suspicion_score}/4, {status}")
    print(f"Flagged domains: {int(results['flagged'].sum())} of {len(results)}")
    if args.known_malicious:
        evaluate(results, args.known_malicious)


if __name__ == "__main__":
    main()
