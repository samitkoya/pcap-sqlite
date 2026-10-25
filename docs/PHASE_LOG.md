# Phase log — local-only improvement

## Phase 0 — audit

- **Changed:** `docs/AUDIT.md` maps `dns_feature_extractor.py`, `detector.py`, `dashboard_server.py`, `web/`, capture provenance, and the existing report. It ranks Windows DB locking, API error exposure, no upload flow, small comparison data, UI states, and tests.
- **Commands/results:** Baseline `.venv` `python -m pip check`, `python -m py_compile dns_feature_extractor.py detector.py dashboard_server.py`, and `node --check web/app.js` exited 0. No original test, build, lint, typecheck, or Lighthouse task existed. `git status --short --branch` showed pre-existing uncommitted cleanup and database changes.
- **Issues fixed during verification:** Restored official portable TShark locally under ignored `.task1/`; `tshark.exe --version` reported 4.4.19.
- **Assumptions:** Course-scale localhost app, no accounts, no public service. See `docs/ASSUMPTIONS.md`.
- **Known issues carried:** Simplistic base-domain splitting and source-label limits.

## Phase 1 — domain research

- **Changed:** `docs/DESIGN_BRIEF.md` compares eight security/network analysis products with primary documentation links. It defines forensic, restrained, legible direction and medium-high data density.
- **Commands/results:** Web research read official Wireshark, Elastic, Splunk, Security Onion, GuardDuty, Datadog, Sentinel, and Zeek material; the brief contains product-specific adoption decisions.
- **Issues fixed during verification:** Kept the approved two-tab information architecture and avoided invented security data.
- **Assumptions:** Benchmark patterns apply to a small local dataset only.
- **Known issues carried:** No generated visual concept, because that tool would write outside the project folder contrary to the user's hard rule.

## Phase 2 — design system

- **Changed:** `web/styles.css` defines neutral/blue/semantic colors, spacing, radii, shadow, z-index, and motion tokens; it raises small text sizes and uses consistent controls and table panels.
- **Commands/results:** Calculated representative token contrast: subtle text on the darkest background was 4.8:1 before being raised further; muted text 7.96:1, blue 7.92:1, red on red-soft 6.64:1, and amber on amber-soft 8.42:1. `node --check web/app.js` passed. No package install/build/typecheck/lint command exists for the vanilla frontend.
- **Issues fixed during verification:** Raised `--subtle` because the earlier value was below 4.5:1 on raised panels; removed decorative gradients/glow from the main layout.
- **Assumptions:** Native controls and inline states cover the app's workflows; modal, toast, and skeleton components would be unused.
- **Known issues carried:** Browser-native select popup appearance varies by OS.

## Phase 3 — UI redesign

- **Changed:** `web/index.html`, `web/app.js`, `web/styles.css`, and `docs/screenshots/dashboard_overview.png`. Overview retains metrics, ranked table, entropy chart; Domain Detail retains rule table, query trace, inspector, type mix, and timeline. Added upload controls, loading/retry, skip link, semantic domain button, and mobile focus handling.
- **Commands/results:** In-app browser upload of real `data/normal.pcap` saved 19 queries/7 domains and selected the new database. Headless system Chrome later checked 360/768/1280/1920 px, all with zero page overflow and zero console/page errors. Keyboard tests switched tabs via arrow keys, opened `example.attack` with Enter, and returned focus after mobile Escape. The screenshot was viewed after capture.
- **Issues fixed during verification:** A new CSP initially blocked the select arrow's `data:` SVG; added `img-src 'self' data:` and reran the browser check cleanly. An initial mobile screenshot caught the drawer mid-transition; a later capture waited for the final transform.
- **Assumptions:** Internal horizontal scrolling for the wide evidence table is acceptable; the page itself must not overflow.
- **Known issues carried:** Tables remain dense on phones by design.

## Phase 4 — backend

- **Changed:** `dashboard_server.py`, `dns_feature_extractor.py`, `detector.py`, `output/*.db`, `data/SOURCES.md`. Upload processing validates size, name, extension and magic, runs PyShark with TShark, writes both required tables, and returns a selectable DB ID. The API owns score thresholds and flagged status.
- **Commands/results:** All ten PCAPs were run through the extractor. TShark query counts and SQLite row counts matched for the three new captures (3,029, 376, 457). All ten bundled DBs reported `PRAGMA integrity_check = ok`, required tables present, and both new indexes present. HTTP tests covered health, valid/invalid thresholds, invalid database, private static path, Host rejection, upload, and readback.
- **Issues fixed during verification:** First Windows upload test failed with `PermissionError [WinError 32]` renaming an open SQLite DB. Explicit connection closure fixed it; the same real-upload test now passes. Raw SQL exception text no longer reaches the browser.
- **Assumptions:** No auth or CORS grant is needed on a loopback-only tool. No public deployment is supported.
- **Known issues carried:** Large uploads can still take time in TShark; upload limit is 25 MiB. `to_sql` CLI writes are not an atomic two-table replacement, while browser uploads use a temporary DB.

## Phase 5 — structure and code quality

- **Changed:** Kept student-readable top-level scripts and `web/`; added `tests/`, `docs/ASSUMPTIONS.md`, `docs/AUDIT.md`, `docs/DESIGN_BRIEF.md`, `docs/CHANGELOG.md`, and this log. `README.md` now gives commands, API details, and an architecture diagram. Local upload folders are ignored by Git.
- **Commands/results:** Python `py_compile`, Node `--check`, `git diff --check`, and `.venv` `pip check` exited 0 after implementation.
- **Issues fixed during verification:** Removed rule values and upload limit from hardcoded frontend data; the API now supplies them.
- **Assumptions:** A React/TypeScript/ESLint/Prettier migration would add framework complexity to a four-day vanilla JS course project. Existing scripts remain the source of truth.
- **Known issues carried:** No static Python type checker is configured; type annotations cover the central server/extractor interfaces.

## Phase 6 — testing, security, performance

- **Changed:** `tests/test_dashboard.py` and `tests/test_features.py` cover real-capture API results, live upload, HTTP validation, entropy, aggregation, and strict rule boundaries. Security measures and SQLite indexes are described above.
- **Commands/results:** `python -m unittest discover -s tests -v` passed 6 tests; `coverage run --source=dashboard_server,dns_feature_extractor,detector -m unittest discover -s tests` passed and `coverage report -m` reported 71% total statement coverage (server 74%, extractor 77%, detector 45%; CLI paths are not exercised by unittest). `pip-audit --local` initially found an advisory for `pip 26.1.2`; after upgrading local pip to 26.2.2, rerun exited 0 with no known vulnerabilities. `pip check` exited 0. Browser functional and keyboard checks passed at four widths.
- **Issues fixed during verification:** Windows DB handle leak, CSP data-image block, and vulnerable local pip version.
- **Assumptions:** 25 MiB upload cap and loopback binding limit exposure; no benchmark from before the redesign is available.
- **Known issues carried:** PyShark 0.6 emits a Python 3.14 event-loop deprecation warning; it did not stop extraction. Packet-level labels and a large-capture performance benchmark are absent.

## Phase 7 — final delivery

- **Changed:** `docs/FINAL_REPORT.md`, `README.md`, `report.md`, `handoff.md`, and the refreshed `docs/screenshots/dashboard_overview.png` provide presentation instructions, truthful results, screenshot, and exact limitations. The current app was restarted on port 8501 and opened in the in-app browser.
- **Commands/results:** `python -m venv .task1/clean-venv` exited 0; the fresh environment installed `requirements.txt` and upgraded its local pip to 26.2.2. Fresh-environment `pip check`, all six tests, and a real `data/normal.pcap` extraction to `.task1/clean-check.db` exited 0. The active `.venv` also passed all six tests, `coverage report -m` (71%), `pip check`, `pip-audit --local` (no known vulnerabilities), Python `py_compile`, Node `--check`, and `git diff --check`. The final headless browser run on port 8501 passed keyboard, threshold, data-switching, mobile drawer, four widths with zero page overflow, and zero console/page errors. `GET /api/health` returned `status=ok`, 11 available databases (ten bundled plus one local browser test upload), `tshark_available=true`; `netstat` showed only `127.0.0.1:8501` listening under PID 24660.
- **Issues fixed during verification:** The old 8501 server was replaced with current code; the temporary 8502 server was stopped. The fresh environment's bundled pip was upgraded after the earlier advisory.
- **Assumptions:** The static frontend has no build or TypeScript pipeline; Python syntax checks, Node syntax checks, tests, and a live browser are its applicable final gates. No before/after Lighthouse claim is possible.
- **Known issues carried:** Source-label limits, iodine miss, unresolved `powerdns.com` flag, large-capture scaling, and PyShark's Python 3.14 deprecation warning. Automatic command review rejected cleanup of an ignored 12 KB failed-test partial DB under `.task1/tmpnbf3bdxw`; it is outside tracked deliverables and does not affect the app.
