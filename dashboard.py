"""Offline, two-tab viewer for the DNS tunneling detector's SQLite output.

Run with ``streamlit run dashboard.py`` from the project directory.
"""

from pathlib import Path
import sqlite3

import altair as alt
import pandas as pd
import streamlit as st

from detector import score_domains


ROOT = Path(__file__).resolve().parent
PAGE_CSS = """<style>
:root {--ink:#101b31;--muted:#5d6b82;--line:#dce3ec;--accent:#2563eb;
       --sidebar:#f6f8fb;--risk:#b42332}
.stApp {background:#fff;color:var(--ink)}
html,body,[data-testid="stAppViewContainer"] {font-family:"Segoe UI",Arial,sans-serif}
[data-testid="stAppDeployButton"],[data-testid="stMainMenu"] {display:none}
.block-container {max-width:1480px;padding:2.2rem 2.55rem 4rem}
[data-testid="stSidebar"] {background:var(--sidebar);border-right:1px solid var(--line)}
[data-testid="stSidebarUserContent"] {padding:1.7rem 1.4rem 2rem}
[data-testid="stSidebar"] label {color:var(--ink);font-size:.88rem;font-weight:600}
[data-testid="stSidebar"] [data-baseweb="select"]>div,
[data-testid="stSidebar"] input {border-color:#cfd8e4;border-radius:6px;background:#fff}
.settings-heading {font-size:1.35rem;font-weight:700;letter-spacing:-.035em;
                   margin:.05rem 0 1.9rem}
.sidebar-section {font-size:.85rem;font-weight:700;color:var(--ink);
                  border-top:1px solid var(--line);padding-top:1.3rem;margin-top:1.45rem}
.sidebar-rule {display:flex;justify-content:space-between;gap:1rem;
               color:var(--muted);font-size:.82rem;line-height:1.45;padding:.52rem 0;
               border-bottom:1px solid #e9edf2}
.sidebar-rule strong {color:var(--ink);font-weight:600;white-space:nowrap}
.sidebar-note {color:var(--muted);font-size:.76rem;line-height:1.45;margin-top:1rem}
h1 {font-size:2.85rem!important;line-height:1.1!important;letter-spacing:-.05em!important;
    font-weight:760!important;color:var(--ink)!important;margin-bottom:1.3rem!important}
h2,h3 {color:var(--ink)!important;letter-spacing:-.03em!important;font-weight:700!important}
h3 {font-size:1.32rem!important;margin-top:.35rem!important}
p {color:var(--muted)}
[data-baseweb="tab-list"] {gap:1.8rem;border-bottom:1px solid var(--line)}
button[data-baseweb="tab"] {font-size:.94rem;font-weight:550;color:var(--muted);
    padding:.55rem .1rem 1rem;letter-spacing:-.01em}
button[data-baseweb="tab"][aria-selected="true"] {color:var(--accent);font-weight:700}
[data-baseweb="tab-highlight"] {background:var(--accent);height:2px}
.metric-strip {display:grid;grid-template-columns:repeat(4,minmax(0,1fr));
               border-bottom:1px solid var(--line);padding:2.25rem 0 2.15rem;margin-bottom:1.65rem}
.metric-item {padding:0 1.75rem;border-right:1px solid var(--line)}
.metric-item:first-child {padding-left:0}.metric-item:last-child {border-right:0}
.metric-label {color:var(--muted);font-size:.85rem;line-height:1.4;margin-bottom:.52rem}
.metric-value {color:var(--ink);font-size:2.45rem;line-height:1.05;font-weight:720;
               letter-spacing:-.045em;font-variant-numeric:tabular-nums}
.metric-value.risk {color:var(--risk)}
.risk-line {color:var(--risk);font-size:1rem;font-weight:650;margin:.1rem 0 .5rem}
.clear-line {color:#206b56;font-size:1rem;font-weight:650;margin:.1rem 0 .5rem}
.detail-meta {font-size:.85rem;color:var(--muted);margin-bottom:1.1rem}
[data-testid="stDataFrame"] {border:1px solid var(--line);border-radius:6px;overflow:hidden}
[data-testid="stAlert"] {border-radius:6px}
[data-testid="stCaptionContainer"] p {font-size:.82rem;line-height:1.45}
@media (max-width:900px) {
  .block-container {padding:1.7rem 1.25rem 3rem}
  h1 {font-size:2.05rem!important}
  .metric-strip {grid-template-columns:repeat(2,minmax(0,1fr));row-gap:1.3rem;padding:1.5rem 0}
  .metric-item {padding:0 1rem}.metric-item:nth-child(odd) {padding-left:0}
  .metric-item:nth-child(2) {border-right:0}
}
@media (max-width:520px) {
  .metric-value {font-size:1.7rem}.metric-label {font-size:.76rem}
  .metric-item {padding:0 .65rem}
}
</style>"""
SUMMARY_COLUMNS = {
    "base_domain", "query_count", "avg_entropy", "max_entropy",
    "unique_query_types", "avg_query_len", "txt_null_ratio",
}
QUERY_COLUMNS = {
    "base_domain", "query_name", "query_len", "subdomain_entropy",
    "query_type", "timestamp",
}


def load_database(path: Path) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Read existing tables without creating or modifying a database."""
    if not path.is_file():
        raise FileNotFoundError(f"Database not found: {path}")
    with sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True) as connection:
        summary = pd.read_sql_query("SELECT * FROM domain_summary", connection)
        queries = pd.read_sql_query("SELECT * FROM dns_queries", connection)
    for table, frame, required in (
        ("domain_summary", summary, SUMMARY_COLUMNS),
        ("dns_queries", queries, QUERY_COLUMNS),
    ):
        missing = required - set(frame.columns)
        if missing:
            raise ValueError(f"{table} is missing columns: {', '.join(sorted(missing))}")
    return score_domains(summary), queries


def frequency_by_minute(queries: pd.DataFrame) -> pd.DataFrame:
    """Accept Unix seconds or ISO timestamps and count queries per minute."""
    raw = queries["timestamp"]
    numeric = pd.to_numeric(raw, errors="coerce")
    if numeric.notna().all():
        timestamps = pd.to_datetime(numeric, unit="s", utc=True, errors="coerce")
    else:
        timestamps = pd.to_datetime(raw, utc=True, errors="coerce")
    valid = timestamps.dropna()
    if valid.empty:
        return pd.DataFrame(columns=["Minute (UTC)", "Queries"])
    return (
        pd.Series(1, index=pd.DatetimeIndex(valid))
        .resample("1min").sum().rename("Queries")
        .rename_axis("Minute (UTC)").reset_index()
    )


def main() -> None:
    st.set_page_config(page_title="DNS Tunneling Detector", page_icon="🔎", layout="wide")
    st.markdown(PAGE_CSS, unsafe_allow_html=True)

    with st.sidebar:
        st.markdown('<div class="settings-heading">Settings</div>', unsafe_allow_html=True)
        candidates = [ROOT / "dns_analysis.db", *sorted((ROOT / "output").rglob("*.db"))]
        labels = [path.relative_to(ROOT).as_posix() for path in candidates]
        preferred = ROOT / "output" / "tunneling.db"
        default_index = candidates.index(preferred) if preferred in candidates else (1 if len(candidates) > 1 and not candidates[0].is_file() else 0)
        selected_path = st.selectbox("Database", labels + ["Other local path…"], index=default_index)
        if selected_path == "Other local path…":
            selected_path = st.text_input("SQLite database path", placeholder="C:/captures/analysis.db")
        threshold = st.slider("Flag threshold", min_value=1, max_value=4, value=2,
                              help="Flag domains whose suspicion score is at least this value.")
        st.caption(f"Score {threshold} or higher is flagged.")
        st.markdown('<div class="sidebar-section">Scoring rules</div>', unsafe_allow_html=True)
        st.markdown("""<div class="sidebar-rule"><span>Average entropy</span><strong>&gt; 3.5</strong></div>
<div class="sidebar-rule"><span>Query count</span><strong>&gt; 20</strong></div>
<div class="sidebar-rule"><span>TXT / NULL ratio</span><strong>&gt; 30%</strong></div>
<div class="sidebar-rule"><span>Average query length</span><strong>&gt; 50</strong></div>
<div class="sidebar-note">Each rule adds one point. The slider changes the view; the SQLite evidence stays unchanged.</div>""",
                    unsafe_allow_html=True)

    st.title("DNS Tunneling Detector")
    if not selected_path:
        st.info("Enter a local SQLite database path to begin.")
        return
    path = Path(selected_path).expanduser()
    if not path.is_absolute():
        path = ROOT / path
    try:
        summary, queries = load_database(path)
    except (OSError, sqlite3.Error, pd.errors.DatabaseError, ValueError) as exc:
        st.warning(str(exc))
        st.info("Select an extracted database from the sidebar, or create the default database:")
        st.code("python dns_feature_extractor.py --pcap data/tunneling.pcap --db dns_analysis.db", language="bash")
        return
    if summary.empty:
        st.info("This database has no domain summaries. Analyze a PCAP containing DNS queries first.")
        return

    summary = summary.sort_values(["suspicion_score", "query_count", "base_domain"], ascending=[False, False, True]).copy()
    summary["flagged"] = summary["suspicion_score"] >= threshold
    summary["Status"] = summary["flagged"].map({True: "Flagged", False: "Below threshold"})
    overview, detail = st.tabs(["Overview", "Domain Detail"])

    with overview:
        metrics = (
            ("DNS queries", f"{len(queries):,}", False),
            ("Domains analyzed", f"{len(summary):,}", False),
            ("Flagged domains", f"{int(summary['flagged'].sum()):,}", summary["flagged"].any()),
            ("Highest suspicion score", f"{int(summary['suspicion_score'].max())} / 4", False),
        )
        cells = "".join(
            f'<div class="metric-item"><div class="metric-label">{label}</div>'
            f'<div class="metric-value{" risk" if risk else ""}">{value}</div></div>'
            for label, value, risk in metrics
        )
        st.markdown(f'<div class="metric-strip" role="group" aria-label="Analysis summary">{cells}</div>',
                    unsafe_allow_html=True)
        st.subheader("Ranked domains")
        st.caption("Highest suspicion first. Orange marks score 2; red marks scores 3–4.")
        ranked = summary[["base_domain", "suspicion_score", "Status", "query_count", "avg_entropy", "max_entropy", "avg_query_len", "txt_null_ratio"]].rename(columns={
            "base_domain": "Domain", "suspicion_score": "Score", "query_count": "Queries",
            "avg_entropy": "Avg. entropy", "max_entropy": "Max. entropy",
            "avg_query_len": "Avg. query length", "txt_null_ratio": "TXT / NULL ratio",
        })

        def highlight(row: pd.Series) -> list[str]:
            if row["Score"] >= threshold:
                color = "background-color: #fff2f3; color: #a52533" if row["Score"] >= 3 else "background-color: #fff5e9; color: #955414"
                return [color] * len(row)
            return [""] * len(row)

        st.dataframe(ranked.style.apply(highlight, axis=1).format({
            "Avg. entropy": "{:.2f}", "Max. entropy": "{:.2f}",
            "Avg. query length": "{:.1f}", "TXT / NULL ratio": "{:.1%}",
        }), hide_index=True, width="stretch")
        st.subheader("Average subdomain entropy")
        st.caption("Top 20 domains by suspicion score · bits per character")
        top = summary.head(20)
        base = alt.Chart(top).encode(y=alt.Y("base_domain:N", title=None, sort=None))
        bars = base.mark_bar(size=30, cornerRadiusEnd=2, color="#2563eb").encode(
            x=alt.X("avg_entropy:Q", title="Average entropy", scale=alt.Scale(domain=[0, max(4, float(top["avg_entropy"].max()) + 0.4)]),
                    axis=alt.Axis(tickCount=9, gridColor="#e5eaf1", labelColor="#5d6b82", titleColor="#5d6b82")),
            tooltip=[alt.Tooltip("base_domain:N", title="Domain"), alt.Tooltip("avg_entropy:Q", title="Average entropy", format=".2f"), alt.Tooltip("suspicion_score:Q", title="Score")],
        )
        labels = base.mark_text(align="left", baseline="middle", dx=8, color="#34435b", fontSize=12).encode(
            x="avg_entropy:Q", text=alt.Text("avg_entropy:Q", format=".2f")
        )
        chart = (bars + labels).properties(height=max(145, min(20, len(top)) * 38))
        st.altair_chart(chart, width="stretch")

    with detail:
        domain = st.selectbox("Select a domain", summary["base_domain"].tolist())
        row = summary.loc[summary["base_domain"] == domain].iloc[0]
        domain_queries = queries.loc[queries["base_domain"] == domain]
        st.subheader(domain)
        if row["flagged"]:
            st.markdown(f'<div class="risk-line">Flagged for review · Score {int(row["suspicion_score"])} / 4</div>',
                        unsafe_allow_html=True)
        else:
            st.markdown(f'<div class="clear-line">Below threshold · Score {int(row["suspicion_score"])} / 4</div>',
                        unsafe_allow_html=True)
        st.markdown(f'<div class="detail-meta">Maximum entropy: {row["max_entropy"]:.2f} · '
                    f'Unique query types: {row["unique_query_types"]}</div>', unsafe_allow_html=True)
        rules = pd.DataFrame([
            ["Average entropy", f"{row['avg_entropy']:.2f}", "> 3.5", row["avg_entropy"] > 3.5],
            ["Query count", str(int(row["query_count"])), "> 20", row["query_count"] > 20],
            ["TXT / NULL ratio", f"{row['txt_null_ratio']:.1%}", "> 30%", row["txt_null_ratio"] > 0.3],
            ["Average query length", f"{row['avg_query_len']:.1f}", "> 50", row["avg_query_len"] > 50],
        ], columns=["Feature", "Observed", "Rule", "Triggered"])
        rules["Triggered"] = rules["Triggered"].map({True: "+1 point", False: "0 points"})
        st.dataframe(rules, hide_index=True, width="stretch")
        st.subheader("Query frequency over time")
        frequency = frequency_by_minute(domain_queries)
        if frequency.empty:
            st.info("No valid timestamps are available for this domain.")
        else:
            timeline = alt.Chart(frequency).mark_line(color="#2563eb", strokeWidth=2.4).encode(
                x=alt.X("Minute (UTC):T", title="Time (UTC)",
                        axis=alt.Axis(format="%H:%M", tickCount=6, labelAngle=0, grid=False,
                                      labelColor="#5d6b82", titleColor="#5d6b82")),
                y=alt.Y("Queries:Q", title="Queries per minute",
                        axis=alt.Axis(tickMinStep=1, tickCount=5, gridColor="#e5eaf1",
                                      labelColor="#5d6b82", titleColor="#5d6b82")),
                tooltip=[alt.Tooltip("Minute (UTC):T", format="%Y-%m-%d %H:%M UTC"), "Queries:Q"],
            ).properties(height=260)
            st.altair_chart(timeline, width="stretch")


if __name__ == "__main__":
    main()
