# DNS Tunneling Detector — project brief

## Goal and time budget

Build a Python information security course project in four days. Detect suspicious DNS tunneling domains in local PCAP captures using explainable thresholds, with no machine learning. The mandatory approved module is **PCAP Analysis**, implemented as real **PCAP → SQLite** extraction.

Day 1: Tasks 1–2. Day 2: Tasks 3–4. Day 3: Tasks 5–6. Day 4: Task 7 and bug fixes.

## Ordered tasks

1. **Environment:** `requirements.txt` with `pyshark`, `pandas`, `scipy`; SQLite is built into Python. Verify tshark/Wireshark and that PyShark reads a real sample PCAP.
2. **Data:** Document public sources and save `data/normal.pcap` and `data/tunneling.pcap`. Normal source: Wireshark sample captures. Tunneling source: public dnscat2/iodine PCAP, preferably a trace with independently documented ground truth. If none can be obtained, report the block; do not silently make synthetic data.
3. **Extraction:** `dns_feature_extractor.py` implements `parse_pcap(filepath) -> pandas.DataFrame` using `pyshark.FileCapture(filepath, display_filter='dns')`. One row per DNS query: `query_name`, `query_len`, `subdomain_entropy` (Shannon entropy of labels before the base domain, via `math.log2`), `query_type`, `timestamp`, `base_domain`. Handle malformed packets individually. `aggregate_by_domain(df)` returns `query_count`, `avg_entropy`, `max_entropy`, `unique_query_types`, `avg_query_len`, `txt_null_ratio`. `save_to_sqlite(df, agg_df, db_path='dns_analysis.db')` writes both `dns_queries` and `domain_summary` via pandas `to_sql`. CLI: `python dns_feature_extractor.py --pcap data/tunneling.pcap --db output/tunneling.db`.
4. **Detection:** `detector.py` has labeled constants for thresholds. The entropy point uses `avg_entropy > 3.5` or (`max_entropy > 4.5` and `txt_null_ratio > 0.3`); the other points use `query_count > 20`, `txt_null_ratio > 0.3`, and `avg_query_len > 50`. This small rule refinement catches the short iodine capture without lowering the default flag threshold. `suspicion_score` remains 0–4; `flagged` means score at least 2. `evaluate` counts false positives only against independently supplied benign labels and reports all other flags as unverified. Standalone CLI reads Task 3 SQLite DB. Explain why the features signal tunneling in docstrings.
5. **Dashboard:** `dashboard_server.py` serves the standalone `web/` HTML/CSS/JavaScript UI and reads local SQLite offline. **Approved layout: two tabs, Overview and Domain Detail.** Overview shows summary stats, flagged count, ranked domain table with red/orange highlighting, entropy bar chart. Sidebar allows live flag threshold changes. Domain Detail selects a domain and may show query frequency over time.
6. **End-to-end:** Run extraction and detection on both PCAPs. Confirm which tunneling domains are flagged and whether normal domains are unflagged. Record counts and ground-truth limits; do not claim precision/recall unsupported by labels.
7. **Report:** 1–2 page `report.md` or PDF with problem statement, features, scoring, dashboard screenshot, limitations, and explicit explanation of the PCAP Analysis/SQLite requirement.

## Final artifacts

`requirements.txt`, both PCAPs or documented source if too large, `dns_feature_extractor.py`, `detector.py`, `dashboard_server.py`, `web/`, `output/*.db` from both real captures, `report.md` or PDF with screenshot, and `README.md` with exact install and extraction/detection/dashboard commands. Do not call the project complete until both real captures have passed the full pipeline and the checklist is verified.

## Capture sources selected so far

- Wireshark Sample Captures: https://wiki.wireshark.org/SampleCaptures (`dns.cap` is `data/normal.pcap`, 19 DNS questions). It is a comparison sample, not certified benign-only ground truth.
- Korving-F DNS tunnel dataset: https://github.com/Korving-F/dns-tunnel-dataset (DNSCAT C2 scenario `bind9/dns.pcap` is `data/tunneling.pcap`, 438 DNS questions). It is a simulated, source-labeled tunnel.
- The 12-query dnscat2 capture from https://github.com/dmachard/datasets-malicious-dns remains as `data/additional/tunneling_dnscat2_12_queries.pcap`; it is not the primary test capture. Four more source-labeled tool captures from the same repository are in `data/additional/`, with corresponding SQLite databases in `output/additional/`.

Exact download URLs and label limits are in `data/SOURCES.md`. Check actual detector output before making test claims. See `handoff.md` for the current verified task state.

Latest UI direction (2026-10-25): `dashboard_server.py` and `web/` are the sole dashboard.

Latest repository direction (2026-10-24): the user requested additional datasets, an organized GitHub-ready project, and a push to `https://github.com/samitkoya/pcap-sqlite.git`. Keep the two mandatory root PCAP and SQLite paths intact while organizing additional data under `data/additional/` and `output/additional/`, and screenshots under `docs/screenshots/`.

Current extension (2026-10-26): the user requested a local-only overhaul, additional real captures, and an upload flow that extracts a user-selected PCAP into SQLite and displays it in the existing two-tab dashboard. Preserve the original seven-task course deliverables and provenance limits. The current local-only instruction supersedes the historical push request above: make local commits on `improve/full-overhaul` and do not push. The three added comparison captures and their results are documented in `data/SOURCES.md`; uploaded captures are stored in ignored local folders and are never assumed benign or malicious.
