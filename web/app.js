"use strict";

const state = {
  analysis: null,
  threshold: 2,
  selectedDomain: null,
  filter: "",
  tab: "overview",
  requestNumber: 0,
};

const $ = (id) => document.getElementById(id);
const number = (value) => Number(value).toLocaleString("en-US");
const decimal = (value, places = 2) => Number(value).toFixed(places);
const percent = (value) => `${(Number(value) * 100).toFixed(1)}%`;

function node(tag, className = "", text = "") {
  const result = document.createElement(tag);
  if (className) result.className = className;
  result.textContent = text;
  return result;
}

function svgNode(tag, attributes = {}) {
  const result = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [name, value] of Object.entries(attributes)) result.setAttribute(name, String(value));
  return result;
}

function sortedDomains() {
  return [...state.analysis.domains].sort((a, b) =>
    b.suspicion_score - a.suspicion_score ||
    b.query_count - a.query_count ||
    a.base_domain.localeCompare(b.base_domain)
  );
}

function isFlagged(domain) {
  return domain.suspicion_score >= state.threshold;
}

function showError(message) {
  $("error-banner").textContent = message;
  $("error-banner").hidden = false;
}

function clearError() {
  $("error-banner").hidden = true;
  $("error-banner").textContent = "";
}

function setTab(tab) {
  state.tab = tab;
  for (const name of ["overview", "detail"]) {
    const active = name === tab;
    $(`tab-${name}`).classList.toggle("is-active", active);
    $(`tab-${name}`).setAttribute("aria-selected", String(active));
    $(`tab-${name}`).tabIndex = active ? 0 : -1;
    $(`panel-${name}`).hidden = !active;
  }
  closeSidebar();
}

function renderMetrics() {
  const domains = state.analysis.domains;
  const values = [
    ["DNS queries", number(state.analysis.query_count), false],
    ["Domains analyzed", number(domains.length), false],
    ["Flagged domains", number(domains.filter(isFlagged).length), domains.some(isFlagged)],
    ["Highest suspicion score", `${Math.max(0, ...domains.map((d) => d.suspicion_score))} / 4`, false],
  ];
  const strip = $("metric-strip");
  strip.replaceChildren();
  for (const [label, value, risk] of values) {
    const item = node("div", "metric");
    item.append(node("span", "metric-label", label));
    item.append(node("strong", `metric-value${risk ? " is-risk" : ""}`, value));
    strip.append(item);
  }
}

function renderRanking() {
  const body = $("ranking-body");
  body.replaceChildren();
  const visible = sortedDomains().filter((domain) =>
    domain.base_domain.toLowerCase().includes(state.filter)
  );
  $("search-empty").hidden = visible.length > 0;

  for (const domain of visible) {
    const flagged = isFlagged(domain);
    const row = node("tr", flagged ? (domain.suspicion_score >= 3 ? "risk-high" : "risk-medium") : "");
    row.dataset.domain = domain.base_domain;
    row.tabIndex = 0;
    row.title = `Open details for ${domain.base_domain}`;
    const cells = [
      domain.base_domain,
      `${domain.suspicion_score} / 4`,
      flagged ? "Flagged" : "Below threshold",
      number(domain.query_count),
      decimal(domain.avg_entropy),
      decimal(domain.max_entropy),
      decimal(domain.avg_query_len, 1),
      percent(domain.txt_null_ratio),
    ];
    for (const [index, value] of cells.entries()) {
      row.append(node("td", index === 2 ? "status" : "", value));
    }
    const open = () => {
      state.selectedDomain = domain.base_domain;
      $("domain-select").value = domain.base_domain;
      renderDetail();
      setTab("detail");
      window.scrollTo({ top: 0, behavior: "smooth" });
    };
    row.addEventListener("click", open);
    row.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        open();
      }
    });
    body.append(row);
  }
}

function renderEntropyChart() {
  const chart = $("entropy-chart");
  chart.replaceChildren();
  const domains = sortedDomains().slice(0, 20);
  if (!domains.length) {
    chart.append(node("p", "empty-state", "No domain summaries are available."));
    return;
  }
  const maximum = Math.max(4, ...domains.map((domain) => domain.avg_entropy));
  for (const domain of domains) {
    const row = node("div", "bar-row");
    const name = node("span", "bar-name", domain.base_domain);
    name.title = domain.base_domain;
    const track = node("div", "bar-track");
    const fill = node("span", "bar-fill");
    fill.style.width = `${Math.max(0, Math.min(100, domain.avg_entropy / maximum * 100))}%`;
    track.append(fill);
    row.append(name, track, node("strong", "bar-value", decimal(domain.avg_entropy)));
    chart.append(row);
  }
  const axis = node("div", "bar-axis");
  for (let index = 0; index <= 4; index++) axis.append(node("span", "", decimal(maximum * index / 4, 1)));
  chart.append(axis, node("div", "bar-axis-label", "Average entropy (bits per character)"));
}

function renderRules(domain) {
  const rules = state.analysis.rules;
  const definitions = [
    ["Average entropy", decimal(domain.avg_entropy), `> ${rules.avg_entropy}`, domain.rule_hits.avg_entropy],
    ["Query count", number(domain.query_count), `> ${rules.query_count}`, domain.rule_hits.query_count],
    ["TXT / NULL ratio", percent(domain.txt_null_ratio), `> ${Math.round(rules.txt_null_ratio * 100)}%`, domain.rule_hits.txt_null_ratio],
    ["Average query length", decimal(domain.avg_query_len, 1), `> ${rules.avg_query_len}`, domain.rule_hits.avg_query_len],
  ];
  const body = $("rules-body");
  body.replaceChildren();
  for (const [label, observed, threshold, hit] of definitions) {
    const row = node("tr");
    row.append(node("td", "", label), node("td", "", observed), node("td", "", threshold));
    row.append(node("td", hit ? "is-hit" : "", hit ? "+1 point" : "0 points"));
    body.append(row);
  }
}

function captureTime(milliseconds) {
  return new Date(milliseconds).toISOString().slice(11, 16);
}

function renderTimeline(domain) {
  const svg = $("timeline-chart");
  svg.replaceChildren();
  const times = state.analysis.queries
    .filter((query) => query.base_domain === domain.base_domain && Number.isFinite(query.timestamp_ms))
    .map((query) => query.timestamp_ms)
    .sort((a, b) => a - b);
  $("timeline-empty").hidden = times.length > 0;
  svg.hidden = times.length === 0;
  if (!times.length) return;

  const span = times[times.length - 1] - times[0];
  let bucket = span <= 20 * 60_000 ? 10_000 : span <= 6 * 60 * 60_000 ? 60_000 : 60 * 60_000;
  bucket = Math.max(bucket, Math.ceil(span / 100 / 1000) * 1000);
  const start = Math.floor(times[0] / bucket) * bucket;
  const end = Math.floor(times[times.length - 1] / bucket) * bucket;
  const counts = [];
  for (let moment = start; moment <= end; moment += bucket) counts.push({ moment, count: 0 });
  for (const time of times) counts[Math.floor((time - start) / bucket)].count++;
  const interval = bucket < 60_000 ? `${bucket / 1000}-second` : bucket < 60 * 60_000 ? `${bucket / 60_000}-minute` : `${bucket / (60 * 60_000)}-hour`;
  $("timeline-description").textContent = `${number(times.length)} queries · ${interval} intervals · capture time`;

  const width = 980, height = 280, left = 48, right = 18, top = 15, bottom = 39;
  const plotWidth = width - left - right, plotHeight = height - top - bottom;
  const highest = Math.max(1, ...counts.map((point) => point.count));
  const ceiling = Math.max(5, Math.ceil(highest / 5) * 5);
  const x = (index) => left + (counts.length === 1 ? plotWidth / 2 : index / (counts.length - 1) * plotWidth);
  const y = (value) => top + plotHeight - value / ceiling * plotHeight;

  for (let tick = 0; tick <= 4; tick++) {
    const value = ceiling * tick / 4;
    const yy = y(value);
    svg.append(svgNode("line", { x1: left, x2: width - right, y1: yy, y2: yy, class: "chart-grid" }));
    const label = svgNode("text", { x: left - 10, y: yy + 4, "text-anchor": "end", class: "chart-axis-text" });
    label.textContent = String(Math.round(value));
    svg.append(label);
  }

  const tickIndices = [...new Set([0, .25, .5, .75, 1].map((fraction) => Math.round(fraction * (counts.length - 1))))];
  for (const index of tickIndices) {
    const label = svgNode("text", { x: x(index), y: height - 12, "text-anchor": index === 0 ? "start" : index === counts.length - 1 ? "end" : "middle", class: "chart-axis-text" });
    label.textContent = captureTime(counts[index].moment);
    svg.append(label);
  }

  if (counts.length > 1) {
    const line = svgNode("polyline", {
      points: counts.map((point, index) => `${x(index).toFixed(1)},${y(point.count).toFixed(1)}`).join(" "),
      class: "chart-line",
    });
    svg.append(line);
  }
  if (counts.length <= 35) {
    counts.forEach((point, index) => {
      const dot = svgNode("circle", { cx: x(index), cy: y(point.count), r: 3.3, class: "chart-dot" });
      const title = svgNode("title");
      title.textContent = `${captureTime(point.moment)} · ${point.count} queries`;
      dot.append(title);
      svg.append(dot);
    });
  }
}

function renderDetail() {
  const domain = state.analysis.domains.find((item) => item.base_domain === state.selectedDomain);
  if (!domain) return;
  $("detail-domain").textContent = domain.base_domain;
  const flagged = isFlagged(domain);
  $("detail-status").className = `detail-status ${flagged ? "is-risk" : "is-clear"}`;
  $("detail-status").textContent = `${flagged ? "Flagged for review" : "Below threshold"} · Score ${domain.suspicion_score} / 4`;
  $("detail-meta").textContent = `Maximum entropy: ${decimal(domain.max_entropy)} · Unique query types: ${number(domain.unique_query_types)}`;
  renderRules(domain);
  renderTimeline(domain);
}

function render() {
  if (!state.analysis) return;
  $("source-file").textContent = state.analysis.filename;
  $("source-note").textContent = state.analysis.source_note;
  $("threshold-value").textContent = `${state.threshold} / 4`;
  renderMetrics();
  renderRanking();
  renderEntropyChart();
  renderDetail();
}

function closeSidebar() {
  $("settings-panel").classList.remove("is-open");
  $("sidebar-scrim").hidden = true;
  $("menu-button").setAttribute("aria-expanded", "false");
}

async function loadAnalysis(databaseId) {
  const requestNumber = ++state.requestNumber;
  clearError();
  $("source-file").textContent = "Loading…";
  try {
    const response = await fetch(`/api/analysis?db=${encodeURIComponent(databaseId)}`);
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || "Could not load the analysis.");
    if (requestNumber !== state.requestNumber) return;
    state.analysis = payload;
    state.selectedDomain = payload.domains.some((domain) => domain.base_domain === state.selectedDomain)
      ? state.selectedDomain : payload.domains[0]?.base_domain || null;
    const select = $("domain-select");
    select.replaceChildren();
    for (const domain of sortedDomains()) {
      const option = node("option", "", domain.base_domain);
      option.value = domain.base_domain;
      select.append(option);
    }
    select.value = state.selectedDomain || "";
    render();
  } catch (error) {
    if (requestNumber === state.requestNumber) showError(error.message);
  }
}

async function start() {
  try {
    const response = await fetch("/api/databases");
    if (!response.ok) throw new Error("Could not list the SQLite databases.");
    const databases = await response.json();
    if (!databases.length) throw new Error("No extracted SQLite databases found. Run dns_feature_extractor.py first.");
    const select = $("database-select");
    for (const database of databases) {
      const option = node("option", "", database.label);
      option.value = database.id;
      select.append(option);
    }
    select.value = databases.some((database) => database.id === "tunneling") ? "tunneling" : databases[0].id;
    await loadAnalysis(select.value);
  } catch (error) {
    showError(error.message);
  }
}

$("tab-overview").addEventListener("click", () => setTab("overview"));
$("tab-detail").addEventListener("click", () => setTab("detail"));
$("database-select").addEventListener("change", (event) => {
  closeSidebar();
  loadAnalysis(event.target.value);
});
$("threshold-input").addEventListener("input", (event) => {
  state.threshold = Number(event.target.value);
  render();
});
$("domain-search").addEventListener("input", (event) => {
  state.filter = event.target.value.trim().toLowerCase();
  if (state.analysis) renderRanking();
});
$("domain-select").addEventListener("change", (event) => {
  state.selectedDomain = event.target.value;
  renderDetail();
});
$("menu-button").addEventListener("click", () => {
  const open = !$("settings-panel").classList.contains("is-open");
  $("settings-panel").classList.toggle("is-open", open);
  $("sidebar-scrim").hidden = !open;
  $("menu-button").setAttribute("aria-expanded", String(open));
});
$("sidebar-scrim").addEventListener("click", closeSidebar);
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeSidebar();
});

start();
