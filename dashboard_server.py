"""Serve the HTML dashboard and read-only data from the project's SQLite files."""

import argparse
import json
import sqlite3
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pandas as pd

from detector import (
    ENTROPY_THRESHOLD,
    QUERY_COUNT_THRESHOLD,
    QUERY_LENGTH_THRESHOLD,
    TXT_NULL_RATIO_THRESHOLD,
    score_domains,
)


ROOT = Path(__file__).resolve().parent
WEB_ROOT = ROOT / "web"
DATABASES = {
    "tunneling": ROOT / "output" / "tunneling.db",
    "normal": ROOT / "output" / "normal.db",
    "dns2tcp": ROOT / "output" / "additional" / "dns2tcp.db",
    "dnscat2": ROOT / "output" / "additional" / "dnscat2.db",
    "dnsextrator": ROOT / "output" / "additional" / "dnsextrator.db",
    "iodine": ROOT / "output" / "additional" / "iodine.db",
    "sods": ROOT / "output" / "additional" / "sods.db",
}
SOURCE_NOTES = {
    "tunneling": "Source-labeled, simulated DNSCAT C2 capture. The label comes from the dataset scenario.",
    "normal": "Wireshark general DNS sample. Its domains are not independently labeled benign.",
    "dns2tcp": "Source-labeled dns2tcp tool capture from dmachard's public sample repository.",
    "dnscat2": "Source-labeled dnscat2 tool capture from dmachard's public sample repository.",
    "dnsextrator": "Source-labeled DNSExfiltrator tool capture from dmachard's public sample repository.",
    "iodine": "Source-labeled iodine tool capture. Its score is below the default threshold.",
    "sods": "Source-labeled sods tool capture from dmachard's public sample repository.",
}


def timestamp_ms(value: str) -> int | None:
    """Convert a stored capture timestamp to milliseconds for chart binning."""
    try:
        moment = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return int(moment.timestamp() * 1000)


def analysis_payload(database_id: str) -> dict:
    """Read the two required tables without modifying the PCAP evidence."""
    path = DATABASES.get(database_id)
    if path is None or not path.is_file():
        raise ValueError("Unknown or unavailable database")

    with sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True) as connection:
        summary = pd.read_sql_query("SELECT * FROM domain_summary", connection)
        query_rows = connection.execute(
            "SELECT query_name, base_domain, query_type, timestamp, query_len, subdomain_entropy "
            "FROM dns_queries ORDER BY timestamp, rowid"
        ).fetchall()

    scored = score_domains(summary)
    domains = []
    for row in scored.itertuples(index=False):
        domains.append({
            "base_domain": str(row.base_domain),
            "query_count": int(row.query_count),
            "avg_entropy": float(row.avg_entropy),
            "max_entropy": float(row.max_entropy),
            "unique_query_types": int(row.unique_query_types),
            "avg_query_len": float(row.avg_query_len),
            "txt_null_ratio": float(row.txt_null_ratio),
            "suspicion_score": int(row.suspicion_score),
            "rule_hits": {
                "avg_entropy": bool(row.avg_entropy > ENTROPY_THRESHOLD),
                "query_count": bool(row.query_count > QUERY_COUNT_THRESHOLD),
                "txt_null_ratio": bool(row.txt_null_ratio > TXT_NULL_RATIO_THRESHOLD),
                "avg_query_len": bool(row.avg_query_len > QUERY_LENGTH_THRESHOLD),
            },
        })

    queries = [
        {
            "query_id": index,
            "query_name": query_name,
            "base_domain": base_domain,
            "query_type": query_type,
            "timestamp_ms": timestamp_ms(timestamp),
            "query_len": int(query_len),
            "subdomain_entropy": float(subdomain_entropy),
        }
        for index, (query_name, base_domain, query_type, timestamp, query_len, subdomain_entropy)
        in enumerate(query_rows)
    ]
    return {
        "database": database_id,
        "filename": path.name,
        "source_note": SOURCE_NOTES[database_id],
        "query_count": len(queries),
        "domains": domains,
        "queries": queries,
        "rules": {
            "avg_entropy": ENTROPY_THRESHOLD,
            "query_count": QUERY_COUNT_THRESHOLD,
            "txt_null_ratio": TXT_NULL_RATIO_THRESHOLD,
            "avg_query_len": QUERY_LENGTH_THRESHOLD,
        },
    }


class DashboardHandler(SimpleHTTPRequestHandler):
    """Serve static assets plus two small JSON endpoints on localhost."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_ROOT), **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        super().end_headers()

    def send_json(self, payload: dict | list, status: int = 200):
        body = json.dumps(payload, allow_nan=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        request = urlsplit(self.path)
        if request.path == "/api/databases":
            self.send_json([
                {"id": key, "label": path.name}
                for key, path in DATABASES.items() if path.is_file()
            ])
            return
        if request.path == "/api/analysis":
            database_id = parse_qs(request.query).get("db", ["tunneling"])[0]
            try:
                self.send_json(analysis_payload(database_id))
            except ValueError as exc:
                self.send_json({"error": str(exc)}, status=400)
            except (sqlite3.Error, pd.errors.DatabaseError, OSError) as exc:
                self.send_json({"error": f"Could not read the database: {exc}"}, status=500)
            return
        super().do_GET()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8501, help="Local dashboard port")
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), DashboardHandler)
    print(f"HTML dashboard: http://127.0.0.1:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
