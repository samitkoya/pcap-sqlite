# Codex project instructions

Read `prompt.md` for the full project brief and `handoff.md` for the latest verified state before changing files. Update `handoff.md` after each completed or blocked task and at the end of a session. Record commands and observed results, not assumed success.

If `handoff.md` says the project is paused, wait for an explicit user request to continue before resuming implementation or tests.

## Project boundaries

- This is a four-day information security course project: a rule-based DNS tunneling detector, with no machine learning.
- The mandatory approved module is **PCAP Analysis: PCAP to SQLite**. Keep the `dns_queries` and `domain_summary` SQLite tables generated from real PCAP queries.
- Use PyShark with tshark for parsing. Verify the backend and actual captures before claiming an end-to-end run. Do not silently replace unavailable tooling or fabricate traffic.
- Keep `dns_feature_extractor.py`, `detector.py`, and `dashboard.py` explainable to a student during a viva.
- The dashboard layout was approved as two tabs: Overview and Domain Detail. Its scope is in `prompt.md`.
- Keep sample provenance and ground truth documented. Never label a capture benign or malicious based only on the detector's output.

## Workflow

Work in the task order in `prompt.md`. For each task, verify the deliverable and report `[TASK N] STATUS: done/blocked | OUTPUT: <paths> | ISSUES: <any>`. If environment setup or a public tunneling PCAP is blocked, report it and stop dependent work. Keep the Day 1 through Day 4 schedule in view.

At handoff, update `handoff.md` with completed work, files, commands that were actually run, results, blockers, and the exact next step. A future chat should use that file as a starting point and verify its current filesystem state.
