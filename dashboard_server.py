"""Serve the HTML dashboard and read-only data from the project's SQLite files."""

import argparse
import json
import logging
import os
import sqlite3
import uuid
from contextlib import closing
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

import pandas as pd
from dns_feature_extractor import aggregate_by_domain, parse_pcap, resolve_tshark_path, save_to_sqlite

from detector import (
    ENTROPY_THRESHOLD,
    FLAG_SCORE_THRESHOLD,
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
    "ctu-normal-4": ROOT / "output" / "additional" / "ctu_normal_4_dns.db",
    "dns2tcp-key": ROOT / "output" / "additional" / "korving_dns2tcp_key.db",
    "dns2tcp-txt": ROOT / "output" / "additional" / "korving_dns2tcp_txt.db",
}
SOURCE_NOTES = {
    "tunneling": "Source-labeled, simulated DNSCAT C2 capture. The label comes from the dataset scenario.",
    "normal": "Wireshark general DNS sample. Its domains are not independently labeled benign.",
    "dns2tcp": "Source-labeled dns2tcp tool capture from dmachard's public sample repository.",
    "dnscat2": "Source-labeled dnscat2 tool capture from dmachard's public sample repository.",
    "dnsextrator": "Source-labeled DNSExfiltrator tool capture from dmachard's public sample repository.",
    "iodine": "Source-labeled iodine tool capture. Its score is below the default threshold.",
    "sods": "Source-labeled sods tool capture from dmachard's public sample repository.",
    "ctu-normal-4": "Stratosphere normal-activity DNS-only capture. Source-level description, not per-domain benign labels.",
    "dns2tcp-key": "Korving-F simulated DNS2TCP scenario using KEY requests; scenario identifies example.attack.",
    "dns2tcp-txt": "Korving-F simulated DNS2TCP scenario using TXT requests; contains tunnel and other resolver activity.",
}
LOG = logging.getLogger(__name__)
STATIC_PATHS = {"/", "/index.html", "/styles.css", "/app.js", "/favicon.svg"}
UPLOAD_ROOT = ROOT / "data" / "uploads"
UPLOAD_DB_ROOT = ROOT / "output" / "uploads"
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
PCAP_MAGIC = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"}
RULE_THRESHOLDS = {
    "avg_entropy": ENTROPY_THRESHOLD,
    "query_count": QUERY_COUNT_THRESHOLD,
    "txt_null_ratio": TXT_NULL_RATIO_THRESHOLD,
    "avg_query_len": QUERY_LENGTH_THRESHOLD,
}
MAX_SCORE = len(RULE_THRESHOLDS)


def available_databases() -> dict[str, tuple[Path, str, str]]:
    """Return bundled captures plus completed local uploads only."""
    result = {
        key: (path, path.name, SOURCE_NOTES[key])
        for key, path in DATABASES.items() if path.is_file()
    }
    if UPLOAD_ROOT.is_dir():
        for metadata_path in UPLOAD_ROOT.glob("*.json"):
            try:
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                upload_id = metadata_path.stem
                db_path = UPLOAD_DB_ROOT / f"{upload_id}.db"
                if db_path.is_file() and upload_id.startswith("upload-"):
                    result[upload_id] = (db_path, f"{metadata['filename']} (upload)",
                                         "User-uploaded capture. Its traffic has no independent ground-truth label.")
            except (OSError, ValueError, KeyError):
                LOG.warning("Skipping invalid upload metadata: %s", metadata_path.name)
    return result


def timestamp_ms(value: str) -> int | None:
    """Convert a stored capture timestamp to milliseconds for chart binning."""
    try:
        moment = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return int(moment.timestamp() * 1000)


def analysis_payload(database_id: str, flag_threshold: int = FLAG_SCORE_THRESHOLD) -> dict:
    """Read the two required tables without modifying the PCAP evidence."""
    if not 1 <= flag_threshold <= MAX_SCORE:
        raise ValueError(f"Flag threshold must be between 1 and {MAX_SCORE}")
    database = available_databases().get(database_id)
    if database is None:
        raise ValueError("Unknown or unavailable database")
    path, label, source_note = database

    with closing(sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)) as connection:
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
            "flagged": bool(row.suspicion_score >= flag_threshold),
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
        "filename": label,
        "source_note": source_note,
        "query_count": len(queries),
        "flagged_count": sum(domain["flagged"] for domain in domains),
        "flag_threshold": flag_threshold,
        "default_flag_threshold": FLAG_SCORE_THRESHOLD,
        "max_score": MAX_SCORE,
        "domains": domains,
        "queries": queries,
        "rules": RULE_THRESHOLDS,
    }


class DashboardHandler(SimpleHTTPRequestHandler):
    """Serve static assets plus two small JSON endpoints on localhost."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_ROOT), **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
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
        if request.path == "/api/health":
            self.send_json({"status": "ok", "available_databases": len(available_databases()),
                            "tshark_available": bool(resolve_tshark_path() and Path(resolve_tshark_path()).is_file())})
            return
        if request.path == "/api/databases":
            self.send_json([
                {"id": key, "label": label}
                for key, (_path, label, _note) in available_databases().items()
            ])
            return
        if request.path == "/api/analysis":
            parameters = parse_qs(request.query, keep_blank_values=True)
            selected = parameters.get("db", ["tunneling"])
            threshold_values = parameters.get("threshold", [str(FLAG_SCORE_THRESHOLD)])
            if set(parameters) - {"db", "threshold"}:
                self.send_json({"error": "Only db and threshold parameters are supported", "code": "invalid_request"}, status=400)
                return
            if len(selected) != 1 or selected[0] not in available_databases():
                self.send_json({"error": "Unknown database", "code": "invalid_database"}, status=400)
                return
            if len(threshold_values) != 1 or threshold_values[0] not in {str(value) for value in range(1, MAX_SCORE + 1)}:
                self.send_json({"error": f"Threshold must be between 1 and {MAX_SCORE}", "code": "invalid_threshold"}, status=400)
                return
            database_id = selected[0]
            try:
                self.send_json(analysis_payload(database_id, int(threshold_values[0])))
            except ValueError as exc:
                self.send_json({"error": str(exc), "code": "invalid_database"}, status=400)
            except (sqlite3.Error, pd.errors.DatabaseError, OSError):
                LOG.exception("Could not read analysis database %s", database_id)
                self.send_json({"error": "Could not read the selected database", "code": "database_error"}, status=500)
            return
        if request.path not in STATIC_PATHS or request.query:
            self.send_error(404, "Not found")
            return
        super().do_GET()

    def do_POST(self):
        if urlsplit(self.path).path != "/api/upload":
            self.send_json({"error": "Unknown endpoint", "code": "not_found"}, status=404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if not 4 <= length <= MAX_UPLOAD_BYTES:
            self.send_json({"error": "PCAP must be between 4 bytes and 25 MiB", "code": "invalid_size"}, status=413)
            return
        filename = Path(unquote(self.headers.get("X-Filename", "")).replace("\\", "/")).name
        suffix = Path(filename).suffix.lower()
        if not filename or suffix not in {".pcap", ".pcapng", ".cap"}:
            self.send_json({"error": "Choose a .pcap, .pcapng, or .cap file", "code": "invalid_file"}, status=400)
            return
        tshark = resolve_tshark_path()
        if not tshark or not Path(tshark).is_file():
            self.send_json({"error": "TShark is unavailable. Install it or set TSHARK_PATH before uploading.",
                            "code": "tshark_unavailable"}, status=503)
            return
        payload = self.rfile.read(length)
        if len(payload) != length or payload[:4] not in PCAP_MAGIC:
            self.send_json({"error": "The file is not a supported PCAP capture", "code": "invalid_pcap"}, status=400)
            return
        upload_id = f"upload-{uuid.uuid4().hex[:12]}"
        UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
        UPLOAD_DB_ROOT.mkdir(parents=True, exist_ok=True)
        capture_path = UPLOAD_ROOT / f"{upload_id}{suffix}"
        temporary_db = UPLOAD_DB_ROOT / f"{upload_id}.partial.db"
        database_path = UPLOAD_DB_ROOT / f"{upload_id}.db"
        metadata_path = UPLOAD_ROOT / f"{upload_id}.json"
        try:
            capture_path.write_bytes(payload)
            queries = parse_pcap(str(capture_path), tshark)
            summary = aggregate_by_domain(queries)
            save_to_sqlite(queries, summary, str(temporary_db))
            os.replace(temporary_db, database_path)
            metadata_path.write_text(json.dumps({"filename": filename,
                                                "imported_at": datetime.now(timezone.utc).isoformat()}),
                                     encoding="utf-8")
        except Exception:
            LOG.exception("Upload extraction failed for %s", upload_id)
            for path in (capture_path, temporary_db, database_path, metadata_path):
                path.unlink(missing_ok=True)
            self.send_json({"error": "Could not extract the capture. Check that it is a valid PCAP and TShark works.",
                            "code": "extraction_failed"}, status=422)
            return
        self.send_json({"id": upload_id, "label": f"{filename} (upload)",
                        "query_count": len(queries), "domain_count": len(summary)}, status=201)


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
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
