"""Extract explainable DNS tunneling features from a PCAP and save them to SQLite."""

import argparse
import asyncio
import math
import logging
import os
import shutil
import sqlite3
from collections import Counter
from contextlib import closing
from pathlib import Path

import pandas as pd
import pyshark


RAW_COLUMNS = [
    "query_name", "query_len", "subdomain_entropy", "query_type",
    "timestamp", "base_domain",
]
QUERY_TYPES = {
    "1": "A", "2": "NS", "5": "CNAME", "6": "SOA", "10": "NULL",
    "12": "PTR", "15": "MX", "16": "TXT", "28": "AAAA", "33": "SRV",
    "35": "NAPTR", "41": "OPT", "43": "DS", "46": "RRSIG",
    "48": "DNSKEY", "255": "ANY",
}
LOG = logging.getLogger(__name__)


def shannon_entropy(value: str) -> float:
    """Measure label randomness; encoded tunnel chunks tend to use many symbols evenly."""
    if not value:
        return 0.0
    length = len(value)
    return -sum((count / length) * math.log2(count / length)
                for count in Counter(value).values())


def split_domain(query_name: str) -> tuple[str, str]:
    """Return subdomain labels and a simple registrable-looking base (last two labels)."""
    labels = query_name.rstrip(".").lower().split(".")
    if len(labels) < 2:
        return "", labels[0] if labels else ""
    # This intentionally uses the last two labels; public suffixes such as co.uk need a PSL.
    return ".".join(labels[:-2]), ".".join(labels[-2:])


def resolve_tshark_path(tshark_path: str | None = None) -> str | None:
    """Use an explicit path, installed PATH executable, or the bundled workspace build."""
    if tshark_path:
        return tshark_path
    configured = os.environ.get("TSHARK_PATH")
    if configured:
        return configured
    installed = shutil.which("tshark")
    if installed:
        return installed
    portable = Path(__file__).resolve().parent / ".task1/WiresharkPortable64/App/Wireshark/tshark.exe"
    return str(portable) if portable.exists() else None


def parse_pcap(filepath: str, tshark_path: str | None = None) -> pd.DataFrame:
    """Read DNS questions; random labels and unusually long names are common tunnel signals."""
    if not Path(filepath).is_file():
        raise FileNotFoundError(f"Capture does not exist: {filepath}")
    resolved_tshark = resolve_tshark_path(tshark_path)
    if not resolved_tshark or not Path(resolved_tshark).is_file():
        raise FileNotFoundError("TShark is unavailable; install it, set TSHARK_PATH, or pass --tshark")
    # Python 3.14 no longer creates a default event loop automatically.
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())

    capture = pyshark.FileCapture(
        filepath, display_filter="dns", tshark_path=resolved_tshark,
        keep_packets=False,
    )
    rows = []
    skipped_malformed = 0
    try:
        for packet in capture:
            try:
                dns = packet.dns
                response = str(getattr(dns, "flags_response", "0")).lower()
                if not dns.qry_name or response in {"1", "true"}:
                    continue
                name = str(dns.qry_name).rstrip(".")
                subdomain, base_domain = split_domain(name)
                qtype = str(getattr(dns, "qry_type", "UNKNOWN"))
                rows.append({
                    "query_name": name,
                    "query_len": len(name),
                    "subdomain_entropy": shannon_entropy(subdomain.lower()),
                    "query_type": QUERY_TYPES.get(qtype, qtype),
                    "timestamp": pd.to_datetime(packet.sniff_time),
                    "base_domain": base_domain,
                })
            except Exception:
                # A malformed or incomplete packet should not discard the rest of the capture.
                skipped_malformed += 1
                continue
    finally:
        capture.close()
    if skipped_malformed:
        LOG.warning("Skipped %d malformed DNS packets in %s", skipped_malformed, filepath)
    return pd.DataFrame(rows, columns=RAW_COLUMNS)


def aggregate_by_domain(df: pd.DataFrame) -> pd.DataFrame:
    """Summarize query behavior; tunnels often repeat encoded labels and favor TXT/NULL."""
    columns = ["base_domain", "query_count", "avg_entropy", "max_entropy",
               "unique_query_types", "avg_query_len", "txt_null_ratio"]
    if df.empty:
        return pd.DataFrame(columns=columns)
    summary = df.groupby("base_domain", dropna=False).agg(
        query_count=("query_name", "size"),
        avg_entropy=("subdomain_entropy", "mean"),
        max_entropy=("subdomain_entropy", "max"),
        unique_query_types=("query_type", "nunique"),
        avg_query_len=("query_len", "mean"),
        txt_null_ratio=("query_type", lambda values:
                        values.isin(["TXT", "NULL"]).sum() / len(values)),
    ).reset_index()
    return summary[columns]


def save_to_sqlite(df: pd.DataFrame, agg_df: pd.DataFrame,
                   db_path: str = "dns_analysis.db") -> None:
    """Persist raw packet queries and domain summaries for the required PCAP-to-SQLite module."""
    destination = Path(db_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(destination)) as connection:
        with connection:
            df.to_sql("dns_queries", connection, if_exists="replace", index=False)
            agg_df.to_sql("domain_summary", connection, if_exists="replace", index=False)
            connection.execute("CREATE INDEX IF NOT EXISTS idx_dns_queries_timestamp ON dns_queries(timestamp)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_dns_queries_domain_time ON dns_queries(base_domain, timestamp)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", required=True, help="Input PCAP/PCAPNG file")
    parser.add_argument("--db", default="dns_analysis.db", help="Output SQLite database")
    parser.add_argument("--tshark", help="Optional path to tshark.exe (or set TSHARK_PATH)")
    args = parser.parse_args()
    try:
        queries = parse_pcap(args.pcap, args.tshark)
    except FileNotFoundError as exc:
        parser.error(str(exc))
    summary = aggregate_by_domain(queries)
    save_to_sqlite(queries, summary, args.db)
    print(f"Saved {len(queries)} DNS queries across {len(summary)} domains to {args.db}")


if __name__ == "__main__":
    main()
