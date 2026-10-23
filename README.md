# Rule-based DNS tunneling detector

A four-day information security course project that turns real DNS packet captures into SQLite data, scores domains with four explainable rules, and displays the results in a local HTML dashboard. It uses PyShark with TShark and **no machine learning**.

## Project layout

```text
dns_feature_extractor.py   PCAP -> dns_queries and domain_summary in SQLite
detector.py                Four-rule domain scoring and CLI
dashboard_server.py        Read-only localhost API and HTML dashboard server
dashboard.py               Original Streamlit dashboard for the course brief
web/                       Standalone HTML, CSS, JavaScript, favicon
data/normal.pcap            Required general DNS comparison capture
data/tunneling.pcap         Required source-labeled DNSCAT C2 capture
data/additional/            Five more source-labeled tunneling PCAPs
data/SOURCES.md             Exact provenance, hashes, and label limits
output/normal.db            SQLite analysis of the comparison capture
output/tunneling.db         SQLite analysis of the primary tunnel capture
output/additional/          SQLite analyses of the extra captures
docs/screenshots/           Verified dashboard screenshots
report.md                  Course report
```

The PCAPs, SQLite databases, screenshots, and application code are included in this repository. The local `.venv/` and portable TShark copy are excluded; install TShark separately after cloning. Third-party capture provenance is in [data/SOURCES.md](data/SOURCES.md).

## Setup on Windows PowerShell

Install Python 3.14 or a compatible Python 3 release and Wireshark with TShark. Make `tshark.exe` available on `PATH`, set `TSHARK_PATH`, or pass `--tshark` to the extraction command. From the repository root:

```powershell
python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
& .\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
tshark --version
```

SQLite comes with Python. The bundled databases let you view results immediately; TShark is needed when rebuilding them from the PCAPs.

## Run the dashboard

```powershell
python dashboard_server.py
```

Open <http://127.0.0.1:8501/>. The server listens on localhost and reads the bundled SQLite files without changing them. Select any of the seven captures in the sidebar. **Overview** shows query and domain counts, a searchable ranked table, and an entropy chart. **Domain Detail** explains the four rule hits and shows query frequency over time. The flag-threshold slider changes the displayed status only. The earlier Streamlit version remains available with `python -m streamlit run dashboard.py --server.port 8503`.

## Rebuild and score the databases

The two required course captures:

```powershell
python dns_feature_extractor.py --pcap data/normal.pcap --db output/normal.db
python dns_feature_extractor.py --pcap data/tunneling.pcap --db output/tunneling.db
python detector.py --db output/normal.db
python detector.py --db output/tunneling.db --known-malicious example.attack
```

The five additional tool captures:

```powershell
python dns_feature_extractor.py --pcap data/additional/tunneling_dns2tcp.pcap --db output/additional/dns2tcp.db
python dns_feature_extractor.py --pcap data/additional/tunneling_dnscat2_12_queries.pcap --db output/additional/dnscat2.db
python dns_feature_extractor.py --pcap data/additional/tunneling_dnsextrator.pcap --db output/additional/dnsextrator.db
python dns_feature_extractor.py --pcap data/additional/tunneling_iodine.pcap --db output/additional/iodine.db
python dns_feature_extractor.py --pcap data/additional/tunneling_sods.pcap --db output/additional/sods.db
python detector.py --db output/additional/iodine.db
```

Each run stores one row per DNS **query** in `dns_queries` and one summary per base domain in `domain_summary`. The detector awards one point each for average subdomain entropy > 3.5, query count > 20, TXT/NULL ratio > 0.3, and average query length > 50. A score of at least 2 is flagged for review. Its base-domain splitter uses the last two labels, so names under multi-part public suffixes may be grouped incorrectly.

## Observed results

| Capture | DNS queries | Domains | Score of observed domain | Flagged at 2/4? |
| --- | ---: | ---: | ---: | --- |
| Wireshark general DNS | 19 | 7 | All 0/4 | No |
| DNSCAT C2 scenario | 438 | 1 | `example.attack` 4/4 | Yes |
| dns2tcp | 22 | 1 | `hsc.fr` 4/4 | Yes |
| dnscat2 short sample | 12 | 1 | `biillpi.com` 2/4 | Yes |
| DNSExfiltrator | 14 | 1 | `hsc.fr` 3/4 | Yes |
| iodine | 12 | 1 | `biillpi.com` 1/4 | **No** |
| sods | 493 | 1 | `hsc.fr` 4/4 | Yes |

The tool labels come from their source repositories, not the detector. The Wireshark sample is not independently labeled benign. These selected captures do not establish a general accuracy or false-positive rate. The iodine miss illustrates a low-volume limitation. See [report.md](report.md) for the course explanation and [data/SOURCES.md](data/SOURCES.md) for original download links and hashes.
