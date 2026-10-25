# Baseline audit — 2026-10-26

## Architecture map

`data/*.pcap` → `dns_feature_extractor.py` (PyShark / TShark, features and aggregation) → `output/*.db` (`dns_queries`, `domain_summary`) → `detector.py` (four rule points) → `dashboard_server.py` (localhost JSON API) → `web/index.html`, `web/styles.css`, `web/app.js` (Overview and Domain Detail). `data/SOURCES.md` owns capture provenance; `report.md` is the course report.

The baseline checkout was already functional for seven bundled captures. It had uncommitted removal of an obsolete Streamlit UI and regenerated SQLite files when this overhaul began; those changes were preserved. The approved standalone dashboard remained the single UI.

## Ranked findings and disposition

| Rank | Finding and evidence | Disposition |
| --- | --- | --- |
| High | No user capture import flow in `dashboard_server.py` or `web/`; presentation was limited to bundled databases. | Added bounded local upload, real PyShark extraction, SQLite persistence, and UI selection. |
| High | `dns_feature_extractor.py` and `dashboard_server.py` used `with sqlite3.connect(...)`, which commits but does not close the connection; Windows blocked the uploaded DB rename in the first integration test. | Explicitly close connections; the same test now passes. |
| High | `dashboard_server.py` returned raw SQLite exception text and accepted arbitrary static paths under `web/`; the API had no health route or strict parameter validation. | Stable JSON errors, static allowlist, health route, validation, logging, headers, localhost Host check. |
| Medium | Rule values and flag decision were duplicated in `web/index.html` and `web/app.js`; server and UI could drift. | Server now supplies rules, score range, threshold, and flagged status for each domain. |
| Medium | `web/app.js` had no visible loading or retry state; tab keyboard behavior and mobile settings focus were incomplete. | Added loading/retry, skip link, arrow/Home/End tab keys, and focus return. |
| Medium | Several labels in `web/styles.css` were 9–11 px, and the prior screenshot in `docs/screenshots/` depicted an older UI. | Raised small text sizes, flattened decorative backgrounds, refreshed screenshot. |
| Medium | Comparison traffic in `data/normal.pcap` held only 19 questions, too small to stress domain ranking. | Added source-described CTU normal DNS capture with 3,029 queries/112 domains. |
| Medium | No automated tests in the baseline repository. | Added boundary and HTTP/upload integration checks under `tests/`. |
| Low | `dns_feature_extractor.py` documented simplistic last-two-label base-domain splitting; `co.uk` and similar suffixes can be grouped incorrectly. | Kept for explainability; documented as a limitation. |
| Low | `dashboard_server.py` loads all queries in one JSON response; large captures could slow the browser. | Kept for course-scale captures; limit browser uploads to 25 MiB and document pagination as future work. |

## Baseline verification actually run

The pre-edit `.venv` `python -m pip check`, Python `py_compile` for three active scripts, and `node --check web/app.js` all exited 0. There was no test suite, package build, typecheck, lint script, or Lighthouse result to run in the original static/Python stack. No claim of a baseline Lighthouse score is made. At the start, TShark was absent from `PATH` and known installation paths; the seven existing databases were viewable but fresh extraction was not reproducible until a project-local official portable copy was restored.

## Backend review notes

There is no auth provider or public user account model; the server is localhost-only. CORS was not enabled. There are two read queries per analysis request (all summaries and all query rows), so no N+1 request loop, but the response and DOM size grow with the capture. Indexes on query timestamp and `(base_domain, timestamp)` now support ordered evidence access. `save_to_sqlite` still uses pandas' SQLite `to_sql` behavior, so a failed CLI rebuild could leave a partial destination; uploads write to a temporary DB before replacement. This distinction is recorded in `docs/FINAL_REPORT.md`.
