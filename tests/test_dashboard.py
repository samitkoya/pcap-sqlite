"""Contract checks against the bundled real-capture SQLite outputs."""

import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from unittest.mock import patch

import dashboard_server
from dashboard_server import DashboardHandler, ROOT, analysis_payload


class DashboardTests(unittest.TestCase):
    def test_real_capture_payloads(self):
        normal = analysis_payload("normal")
        tunnel = analysis_payload("tunneling")
        self.assertEqual((normal["query_count"], len(normal["domains"])), (19, 7))
        self.assertEqual((tunnel["query_count"], len(tunnel["domains"])), (438, 1))
        self.assertEqual(tunnel["domains"][0]["base_domain"], "example.attack")
        self.assertEqual(tunnel["domains"][0]["suspicion_score"], 4)
        self.assertEqual(tunnel["flagged_count"], 1)
        self.assertEqual(analysis_payload("tunneling", 4)["flag_threshold"], 4)
        self.assertEqual(analysis_payload("normal", 1)["flagged_count"], 0)

    def test_http_contract(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), DashboardHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            with urlopen(f"{base}/api/health") as response:
                self.assertEqual(response.status, 200)
                self.assertEqual(json.load(response)["status"], "ok")
                self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
            with urlopen(f"{base}/api/analysis?db=normal") as response:
                self.assertEqual(json.load(response)["query_count"], 19)
            with urlopen(f"{base}/api/analysis?db=tunneling&threshold=4") as response:
                payload = json.load(response)
                self.assertEqual((payload["flag_threshold"], payload["flagged_count"]), (4, 1))
            with self.assertRaises(HTTPError) as error:
                urlopen(f"{base}/api/analysis?db=normal&threshold=9")
            self.assertEqual(error.exception.code, 400)
            self.assertEqual(json.load(error.exception)["code"], "invalid_threshold")
            error.exception.close()
            with self.assertRaises(HTTPError) as error:
                urlopen(f"{base}/api/analysis?db=../../secrets")
            self.assertEqual(error.exception.code, 400)
            self.assertEqual(json.load(error.exception)["code"], "invalid_database")
            error.exception.close()
            with self.assertRaises(HTTPError) as error:
                urlopen(f"{base}/handoff.md")
            self.assertEqual(error.exception.code, 404)
            error.exception.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_upload_extracts_real_capture(self):
        tshark = dashboard_server.resolve_tshark_path()
        if not tshark or not dashboard_server.Path(tshark).is_file():
            self.skipTest("TShark is unavailable")
        with tempfile.TemporaryDirectory(dir=ROOT / ".task1") as directory:
            upload_root = dashboard_server.Path(directory) / "captures"
            db_root = dashboard_server.Path(directory) / "databases"
            with patch.object(dashboard_server, "UPLOAD_ROOT", upload_root), \
                 patch.object(dashboard_server, "UPLOAD_DB_ROOT", db_root):
                server = ThreadingHTTPServer(("127.0.0.1", 0), DashboardHandler)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    base = f"http://127.0.0.1:{server.server_port}"
                    capture = (ROOT / "data" / "normal.pcap").read_bytes()
                    request = Request(f"{base}/api/upload", data=capture, method="POST",
                                      headers={"X-Filename": "normal.pcap",
                                               "Content-Type": "application/octet-stream"})
                    with urlopen(request, timeout=30) as response:
                        self.assertEqual(response.status, 201)
                        result = json.load(response)
                    self.assertEqual((result["query_count"], result["domain_count"]), (19, 7))
                    with urlopen(f"{base}/api/analysis?db={result['id']}") as response:
                        self.assertEqual(json.load(response)["query_count"], 19)
                    self.assertTrue((db_root / f"{result['id']}.db").is_file())
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
