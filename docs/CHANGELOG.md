# Local overhaul changelog

## 2026-10-26

- Preserved the approved PyShark/TShark → SQLite → four-rule detector → two-tab dashboard workflow. Added one source-described normal DNS capture and two DNS2TCP scenarios. Source URLs, hashes, observed counts, and label limits are in `data/SOURCES.md`.
- Added localhost PCAP upload and extraction with a 25 MiB limit, capture signature check, temporary database, and local-only ignored storage. Uploaded captures are not assigned a truth label.
- Moved rule thresholds, flag decisions, score range, score summaries, upload constraints, and source notes to the Python API. The browser handles display, navigation, filtering, and charts.
- Closed SQLite connections explicitly to fix a Windows file-lock failure discovered by the upload integration test. Added timestamp and `(base_domain, timestamp)` indexes to the two-table output without changing columns; rebuilt all ten bundled databases through the real PyShark pipeline.
- Added request validation, stable JSON errors, a health route, Host validation, a static-file allowlist, security headers, and server-side error logging. Existing `GET /api/analysis?db=...` calls still work. `threshold=1..4` is an additive parameter; the response has additive fields including `flagged`, `flagged_count`, and `max_score`. Clients using only older fields need no migration.
- Improved loading/error/retry feedback, keyboard tabs and domain links, mobile drawer focus, type scale, and contrast. Refreshed the report screenshot.
- Added Python unit and HTTP/upload integration tests. No runtime dependency was added. `coverage` and `pip-audit` were installed **only in the ignored local `.venv`** because the requested final workflow calls for coverage and a dependency audit. The audit initially identified an advisory against `pip 26.1.2`; upgrading this local environment to `pip 26.2.2` cleared it. Neither tool was added to `requirements.txt`.

## Migration notes

The `dns_queries` and `domain_summary` table columns and detector thresholds are unchanged. Existing SQLite files can still be read. Re-run `dns_feature_extractor.py` on an older capture to add the new indexes. Local user uploads produced before this index change remain readable without migration. `POST /api/upload` and additional response fields are optional additions; the server still accepts the original database-only analysis URL.
