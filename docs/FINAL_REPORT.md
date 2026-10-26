# Final report — DNS tunneling detector overhaul

The current repository layout is documented in the root [`README.md`](../README.md). The original CLI commands still work; their implementations now live in `pcap_sqlite/`, static files in `web/assets/`, and project instructions in `.codex/`. The feature work was subsequently integrated into `main`, and the feature branch was deleted.

## What is ready

The four-day course project remains a rule-based **real PCAP → PyShark/TShark → SQLite → detector → two-tab dashboard** pipeline. Ten public captures and ten generated SQLite databases are bundled. The mandatory `dns_queries` and `domain_summary` tables, four default scoring rules, and original root capture/database paths are preserved. The dashboard can apply different cutoffs to a view without rewriting SQLite evidence. A user can upload a PCAP in the local dashboard; the server extracts it through the same backend, saves both tables, and opens the result. The dashboard keeps Overview and Domain Detail, with ranked domains, rule evidence, a query trace, type mix, and timeline.

## Before and after

| Area | Baseline observed | Current verified state |
| --- | --- | --- |
| Bundled evidence | Seven captures/databases, including a 19-query general DNS comparison | Ten captures/databases; added CTU DNS comparison (3,029 queries/112 domains) and two DNS2TCP scenarios |
| User capture analysis | No browser upload path | Local 25 MiB PCAP upload, real PyShark extraction, SQLite persistence, and immediate dashboard selection |
| Rule ownership | Sidebar rule values and flag threshold decision repeated in browser code | Server supplies rule values, score range, flag decisions, counts, and upload constraints |
| HTTP behavior | Raw database exceptions could reach clients; no health route | Stable JSON errors, health route, parameter and Host validation, file allowlist, security headers |
| SQLite write on Windows | Open connection blocked a new DB rename in the first upload test | Explicit closure; the same end-to-end test now passes |
| Verification | No repository tests or baseline Lighthouse result | Six Python tests, 71% statement coverage, browser checks at four widths, and a clean dependency audit after local pip upgrade |

## Verification evidence

- All ten bundled PCAPs were re-extracted with a verified project-local TShark 4.4.19. All ten SQLite files passed `PRAGMA integrity_check = ok`, contained both required tables, and contained timestamp/domain-time indexes. The three added captures had matching TShark and SQLite query counts: 3,029, 376, and 457.
- The default main tunnel has 438 queries, one domain, and `example.attack` at 4/4. The stronger normal comparison has 3,029 queries, 112 domains, and zero flags at the default threshold. The revised entropy rule flags the 12-query iodine sample at 2/4. DNS2TCP KEY flags `example.attack` at 2/4. DNS2TCP TXT flags `example.attack` and `powerdns.com` at 3/4; the latter is explicitly shown as unverified.
- The earlier overhaul passed six tests, including a real PCAP upload and readback. The current layout adds a seventh path/link test; `python -m unittest discover -s tests -v` passes all seven. `node --check web/assets/app.js`, Python `py_compile`, and `git diff --check` pass. The earlier 71% coverage measurement applies to the pre-restructure code layout; it was not rerun here.
- In-app browser upload of `data/normal.pcap` saved and displayed 19 queries/7 domains. Headless Chrome verified server-backed threshold changes, keyboard tab navigation, Enter on a domain, mobile drawer Escape focus return, and zero page overflow at 360, 768, 1280, and 1920 px. The final browser pass had zero console/page errors. The report image at `docs/screenshots/dashboard_overview.png` was refreshed and visually inspected.
- The local `pip-audit --local` first reported a known vulnerability for `pip 26.1.2`; upgrading only the ignored `.venv` to `pip 26.2.2` made the rerun report no known vulnerabilities. `coverage` and `pip-audit` were local verification tools only; no runtime dependency was added.
- A fresh project-local environment under ignored `.task1/clean-venv` installed `requirements.txt`, passed `pip check` and all six tests, and extracted the real `normal.pcap` to `.task1/clean-check.db` (19 queries/7 domains). The final server at `http://127.0.0.1:8501/` returned health `ok`, ten bundled databases plus one local test upload, and `tshark_available=true`. Only port 8501 remained listening.

No baseline API timing or Lighthouse run was available, so a before/after speedup or Lighthouse improvement is **not claimed**. A local warm read of the final server measured median responses of 7.3 ms for the 116,241-byte main tunnel JSON and 18.1 ms for the 597,209-byte CTU JSON (median of three reads after one warm-up); these are environment-specific observations, not a throughput guarantee. The frontend is static and has no build/bundle step.

## Known issues and limits

1. **Truth labels and rule tuning:** The CTU capture has a source-level normal-activity description, not per-domain labels. The three `powerdns.com` TXT queries match PowerDNS's documented security-status polling pattern, but the capture still has no independent domain-level label. The revised entropy rule was chosen after seeing the iodine miss, so the iodine result is not independent validation. The selected data cannot establish general precision, recall, or a false-positive rate.
2. **Domain grouping:** The last-two-label splitter mishandles multi-part public suffixes. Query rows also lack source/destination IP and DNS transaction IDs, limiting duplicate and traffic-role analysis.
3. **Scale:** The analysis API sends every query row and the frontend renders the selected domain trace. A large capture within the 25 MiB upload bound could be slow. Add pagination and a parse timeout before treating this as a production multi-user service.
4. **Tooling:** TShark is required for fresh extraction and is not committed. The local portable copy lives in ignored `.task1/`. The extractor now passes an explicitly owned event loop to PyShark 0.6 and closes it after parsing; the iodine capture re-extracted under Python 3.14 with `-W default` without the earlier warning.
5. **Atomicity:** Browser uploads write a temporary SQLite DB before rename. Direct CLI `save_to_sqlite` uses pandas `to_sql` and can leave a partial destination if writing fails halfway; a future revision could give the CLI the same temporary-file strategy.
6. **Review scope:** The app is loopback-only with no authentication, rate limiter, or public-service deployment design. Browser-native select menus may look different across operating systems. No Lighthouse score or large-capture benchmark was obtained.
7. **Ignored QA residue:** Automatic command review rejected removal of one 12 KB partial database left by the initially failed Windows upload test under `.task1/tmpnbf3bdxw`. It is ignored by Git, is not exposed by the server, and does not affect the delivered app.

## Prioritized backlog

1. Add packet identity, client/server addresses, DNS transaction IDs, and a documented deduplication analysis while preserving current table columns through a migration.
2. Acquire independently labeled per-domain comparison data and validate flagged domains with manual packet evidence before interpreting the tuned rule as general performance.
3. Paginate query reads and render a bounded trace for larger captures; add upload processing timeouts and cancellation.
4. Improve base-domain extraction with a public suffix list only if the extra dependency is justified for the course scope.

## Exact local commands

From the repository root in PowerShell, install Python dependencies and make TShark available on `PATH` or via `TSHARK_PATH`:

```powershell
python -m venv .venv
& .\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
tshark --version
python dns_feature_extractor.py --pcap data/normal.pcap --db output/normal.db
python dns_feature_extractor.py --pcap data/tunneling.pcap --db output/tunneling.db
python detector.py --db output/tunneling.db --known-malicious example.attack
python -m unittest discover -s tests -v
node --check web/assets/app.js
python dashboard_server.py --port 8501
```

Open `http://127.0.0.1:8501/`, choose a bundled database or upload a local PCAP, and inspect both tabs. The server listens only on `127.0.0.1`. See the root [`README.md`](../README.md) for capture commands and API details, [`data/SOURCES.md`](../data/SOURCES.md) for provenance, [`PHASE_LOG.md`](PHASE_LOG.md) for earlier phase checks, and [`.codex/handoff.md`](../.codex/handoff.md) for the latest verified state. Current work is on `main`.
