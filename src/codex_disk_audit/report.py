from __future__ import annotations

import json
from pathlib import Path

from .models import CleanupUnit, ScanConfig
from .utils import windows_path_to_file_uri


def render_report_html(output_dir: Path, units: list[CleanupUnit], summary: dict, config: ScanConfig) -> Path:
    findings = []
    for unit in units:
        payload = unit.to_dict()
        payload["open_uri"] = windows_path_to_file_uri(unit.root_path)
        findings.append(payload)

    data = {
        "summary": summary,
        "config": {
            "scan_root": config.scan_root,
            "reasoning_provider": config.reasoning_provider,
            "fallback_provider": config.fallback_provider,
            "web_enrichment_provider": config.web_enrichment_provider,
            "reasoning_max_units": config.reasoning.max_units,
        },
        "findings": findings,
    }
    target = output_dir / "report.html"
    target.write_text(_build_html(data), encoding="utf-8")
    return target


def _build_html(data: dict) -> str:
    json_blob = json.dumps(data).replace("</", "<\\/")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Codex Disk Audit Report</title>
  <style>
    :root {{
      --bg: #f6f2eb;
      --panel: #fffdf8;
      --ink: #1f2630;
      --muted: #667085;
      --border: #dbcdbd;
      --accent: #0f766e;
      --low: #0f766e;
      --medium: #b45309;
      --high: #b42318;
      --badge-bg: #f3ece1;
      --shadow: 0 16px 40px rgba(59, 39, 14, 0.08);
      --mono: "Cascadia Code", "Consolas", monospace;
      --sans: "Segoe UI", "Trebuchet MS", sans-serif;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background:
        radial-gradient(circle at top left, rgba(15, 118, 110, 0.15), transparent 35%),
        radial-gradient(circle at top right, rgba(194, 65, 12, 0.10), transparent 30%),
        var(--bg);
      color: var(--ink);
      font-family: var(--sans);
    }}
    a {{ color: var(--accent); }}
    .shell {{ width: min(1480px, calc(100vw - 32px)); margin: 24px auto 40px; display: grid; gap: 18px; }}
    .hero, .toolbar, .charts, .table-wrap, .drawer {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 22px;
      box-shadow: var(--shadow);
      padding: 18px;
    }}
    .hero {{ padding: 24px; }}
    .hero h1 {{ margin: 0 0 8px; font-size: 2rem; }}
    .hero p, .meta {{ color: var(--muted); line-height: 1.45; }}
    .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-top: 18px; }}
    .card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 18px; padding: 16px; }}
    .label {{ font-size: 0.85rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.08em; }}
    .value {{ margin-top: 6px; font-size: 1.6rem; font-weight: 700; }}
    .filters {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; }}
    .filters input, .filters select {{ width: 100%; border: 1px solid var(--border); border-radius: 12px; padding: 10px 12px; font: inherit; background: #fff; }}
    .charts {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; }}
    .chart h2, .table-wrap h2, .drawer h2 {{ margin: 0 0 12px; font-size: 1rem; }}
    .bar-row {{ display: grid; grid-template-columns: 140px 1fr 88px; align-items: center; gap: 10px; margin-bottom: 10px; font-size: 0.92rem; }}
    .bar {{ height: 12px; border-radius: 999px; background: #eadfd2; overflow: hidden; }}
    .bar > span {{ display: block; height: 100%; background: linear-gradient(90deg, var(--accent), #14b8a6); }}
    .table-scroll {{ overflow: auto; }}
    table {{ width: 100%; border-collapse: collapse; min-width: 1480px; }}
    th, td {{ text-align: left; vertical-align: top; padding: 12px 10px; border-top: 1px solid #ece1d4; font-size: 0.92rem; }}
    th button {{ border: 0; background: transparent; font: inherit; font-weight: 700; color: inherit; cursor: pointer; padding: 0; }}
    td.path {{ font-family: var(--mono); font-size: 0.83rem; color: #344054; max-width: 280px; word-break: break-word; }}
    .badge {{
      display: inline-flex; align-items: center; gap: 6px; border-radius: 999px; padding: 4px 10px; font-size: 0.78rem;
      font-weight: 700; background: var(--badge-bg); border: 1px solid rgba(0,0,0,0.06); text-transform: uppercase; letter-spacing: 0.04em;
    }}
    .risk-low {{ color: var(--low); }}
    .risk-medium {{ color: var(--medium); }}
    .risk-high {{ color: var(--high); }}
    .confidence-high {{ color: var(--low); }}
    .confidence-medium {{ color: var(--medium); }}
    .confidence-low {{ color: var(--high); }}
    .actions {{ display: flex; gap: 8px; flex-wrap: wrap; }}
    .actions a, .actions button {{ border-radius: 999px; border: 1px solid var(--border); padding: 7px 12px; background: #fff; color: inherit; text-decoration: none; font: inherit; cursor: pointer; }}
    .drawer-grid {{ display: grid; gap: 10px; }}
    .drawer pre {{ white-space: pre-wrap; font-family: var(--mono); background: #f8f4ed; padding: 12px; border-radius: 14px; border: 1px solid #e5d7c8; font-size: 0.82rem; overflow: auto; }}
    .list {{ margin: 0; padding-left: 18px; }}
  </style>
</head>
<body>
  <div class="shell">
    <section class="hero">
      <h1>Codex Disk Audit</h1>
      <p>Audit-only cleanup triage for <strong id="scanRoot"></strong>. Requested reasoning provider: <strong id="requestedProvider"></strong>. Fallback provider: <strong id="fallbackProvider"></strong>. Web support provider: <strong id="webProvider"></strong>. Reasoning max units: <strong id="reasoningMaxUnits"></strong>.</p>
      <div class="cards" id="summaryCards"></div>
      <div id="reasoningMeta" class="meta" style="margin-top:12px;"></div>
      <div id="reviewFirstPanel" class="meta" style="margin-top:16px;"></div>
    </section>
    <section class="toolbar">
      <div class="filters">
        <input id="queryInput" type="search" placeholder="Search name, path, reason, sample files">
        <select id="riskFilter"><option value="">All risks</option></select>
        <select id="confidenceFilter"><option value="">All confidence</option></select>
        <select id="categoryFilter"><option value="">All categories</option></select>
        <select id="zoneFilter"><option value="">All zones</option></select>
        <select id="unitTypeFilter"><option value="">All unit types</option></select>
        <select id="reasoningFilter"><option value="">All reasoning modes</option></select>
        <input id="sizeFilter" type="number" min="0" step="1" placeholder="Min size (MB)">
        <input id="dateFromFilter" type="date" title="Modified on or after">
        <input id="dateToFilter" type="date" title="Modified on or before">
        <select id="sortKey">
          <option value="priority">Sort: default priority</option>
          <option value="review_priority_score">Sort: review first score</option>
          <option value="size">Sort: size</option>
          <option value="risk">Sort: risk</option>
          <option value="confidence">Sort: confidence</option>
          <option value="modified">Sort: modified</option>
          <option value="name">Sort: name</option>
        </select>
      </div>
      <div class="meta">Browser file:// behavior varies. Grouped and hybrid units always open their root folder instead of any specific file.</div>
    </section>
    <section class="charts">
      <div class="chart"><h2>Space by Category</h2><div id="categoryChart"></div></div>
      <div class="chart"><h2>Units by Reasoning Mode</h2><div id="modeChart"></div></div>
    </section>
    <section class="table-wrap">
      <h2>Cleanup Units</h2>
      <div class="table-scroll">
        <table>
          <thead>
            <tr>
              <th><button data-sort="name">Name</button></th>
              <th><button data-sort="review_priority_score">Review First</button></th>
              <th><button data-sort="path">Path</button></th>
              <th><button data-sort="unit_type">Unit Type</button></th>
              <th><button data-sort="category">Category</button></th>
              <th><button data-sort="zone">Zone</button></th>
              <th><button data-sort="risk">Risk</button></th>
              <th><button data-sort="confidence">Confidence</button></th>
              <th><button data-sort="size">Total Size</button></th>
              <th><button data-sort="file_count">File Count</button></th>
              <th>Reasoning Mode</th>
              <th>Fallback</th>
              <th>Failure Reason</th>
              <th>Decision Focus</th>
              <th>Recommendation</th>
              <th>Reason Summary</th>
              <th><button data-sort="modified">Last Modified</button></th>
              <th>Evidence Source</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="resultsBody"></tbody>
        </table>
      </div>
    </section>
    <section class="drawer">
      <h2>Details</h2>
      <div id="detailPanel" class="drawer-grid"><div class="meta">Select a cleanup unit to inspect deterministic evidence, reasoning output, uncertainty, counterarguments, citations, and fallback behavior.</div></div>
    </section>
  </div>
  <script>
    const DATA = {json_blob};
    const state = {{ sortKey: "priority", sortDirection: "desc", activeId: null }};
    const riskRank = {{ low: 0, medium: 1, high: 2 }};
    const confidenceRank = {{ low: 0, medium: 1, high: 2 }};
    const priorityRank = {{ review_first: 0, review_next: 1, review_later: 2, low_yield: 3, not_actionable: 4 }};

    function titleCase(value) {{
      return String(value || "").replace(/_/g, " ").replace(/\\b\\w/g, (m) => m.toUpperCase());
    }}
    function formatBytes(bytes) {{
      const units = ["B", "KB", "MB", "GB", "TB"];
      let value = Number(bytes || 0);
      let unit = units[0];
      for (const current of units) {{
        unit = current;
        if (value < 1024 || current === units[units.length - 1]) break;
        value /= 1024;
      }}
      return unit === "B" ? `${{Math.round(value)}} ${{unit}}` : `${{value.toFixed(1)}} ${{unit}}`;
    }}
    function uniqueValues(key) {{
      return [...new Set(DATA.findings.map((item) => item[key]).filter(Boolean))].sort();
    }}
    function populateFilters() {{
      const mappings = [
        ["riskFilter", "risk"],
        ["confidenceFilter", "confidence_label"],
        ["categoryFilter", "category"],
        ["zoneFilter", "zone"],
        ["unitTypeFilter", "unit_type"],
        ["reasoningFilter", "reasoning_provider"],
      ];
      for (const [id, key] of mappings) {{
        const select = document.getElementById(id);
        for (const value of uniqueValues(key)) {{
          const option = document.createElement("option");
          option.value = value;
          option.textContent = titleCase(value);
          select.appendChild(option);
        }}
      }}
      document.getElementById("scanRoot").textContent = DATA.config.scan_root;
      document.getElementById("requestedProvider").textContent = titleCase(DATA.config.reasoning_provider);
      document.getElementById("fallbackProvider").textContent = titleCase(DATA.config.fallback_provider);
      document.getElementById("webProvider").textContent = titleCase(DATA.config.web_enrichment_provider);
      document.getElementById("reasoningMaxUnits").textContent = String(DATA.config.reasoning_max_units || "");
    }}
    function getFilters() {{
      return {{
        query: document.getElementById("queryInput").value.trim().toLowerCase(),
        risk: document.getElementById("riskFilter").value,
        confidence: document.getElementById("confidenceFilter").value,
        category: document.getElementById("categoryFilter").value,
        zone: document.getElementById("zoneFilter").value,
        unitType: document.getElementById("unitTypeFilter").value,
        reasoningProvider: document.getElementById("reasoningFilter").value,
        sizeMb: Number(document.getElementById("sizeFilter").value || 0),
        dateFrom: document.getElementById("dateFromFilter").value,
        dateTo: document.getElementById("dateToFilter").value,
      }};
    }}
    function matchesFilters(item, filters) {{
      if (filters.risk && item.risk !== filters.risk) return false;
      if (filters.confidence && item.confidence_label !== filters.confidence) return false;
      if (filters.category && item.category !== filters.category) return false;
      if (filters.zone && item.zone !== filters.zone) return false;
      if (filters.unitType && item.unit_type !== filters.unitType) return false;
      if (filters.reasoningProvider && item.reasoning_provider !== filters.reasoningProvider) return false;
      if (filters.sizeMb && item.total_size_bytes < filters.sizeMb * 1024 * 1024) return false;
      if (filters.dateFrom && item.display_modified_at && item.display_modified_at < filters.dateFrom) return false;
      if (filters.dateTo && item.display_modified_at && item.display_modified_at > filters.dateTo) return false;
      if (filters.query) {{
        const haystack = [
          item.name, item.path, item.reason_summary, item.recommendation, item.grouping_logic,
          item.reasoning_provider, item.fallback_provider || "", item.decision_focus || "", item.review_priority || "",
          item.provider_failure_reason || "", item.provider_failure_detail || "",
          ...(item.sample_files || []).map((sample) => sample.path),
        ].join(" ").toLowerCase();
        if (!haystack.includes(filters.query)) return false;
      }}
      return true;
    }}
    function sortItems(items) {{
      const direction = state.sortDirection === "asc" ? 1 : -1;
      return [...items].sort((a, b) => {{
        if (state.sortKey === "priority") {{
          return (priorityRank[a.review_priority] - priorityRank[b.review_priority]) || (b.review_priority_score - a.review_priority_score) || (b.total_size_bytes - a.total_size_bytes) || (riskRank[a.risk] - riskRank[b.risk]) || (b.confidence_score - a.confidence_score);
        }}
        if (state.sortKey === "review_priority_score") return direction * ((a.review_priority_score || 0) - (b.review_priority_score || 0));
        if (state.sortKey === "size") return direction * (a.total_size_bytes - b.total_size_bytes);
        if (state.sortKey === "risk") return direction * ((riskRank[a.risk] || 0) - (riskRank[b.risk] || 0));
        if (state.sortKey === "confidence") return direction * ((confidenceRank[a.confidence_label] || 0) - (confidenceRank[b.confidence_label] || 0));
        if (state.sortKey === "modified") return direction * String(a.display_modified_at || "").localeCompare(String(b.display_modified_at || ""));
        return direction * String(a[state.sortKey] || "").localeCompare(String(b[state.sortKey] || ""));
      }});
    }}
    function filteredItems() {{
      return sortItems(DATA.findings.filter((item) => matchesFilters(item, getFilters())));
    }}
    function renderSummary(items) {{
      const totalBytes = items.reduce((sum, item) => sum + item.total_size_bytes, 0);
      const counts = items.reduce((acc, item) => {{
        acc[item.reasoning_provider] = (acc[item.reasoning_provider] || 0) + 1;
        return acc;
      }}, {{}});
      const fallbackLimitCount = items.filter((item) => item.reasoning_status === "fallback_limit").length;
      const fallbackFailureCount = items.filter((item) => item.fallback_provider && item.reasoning_status !== "fallback_limit").length;
      const cards = [
        ["Cleanup Units", items.length],
        ["Candidate Size", formatBytes(totalBytes)],
        ["Review First", items.filter((item) => item.review_priority === "review_first").length],
        ["Codex Local", counts.codex_local || 0],
        ["Deterministic", counts.deterministic || 0],
        ["OpenAI API", counts.openai_api || 0],
        ["Fallback: Max Units", fallbackLimitCount],
        ["Fallback: Provider", fallbackFailureCount],
      ];
      const target = document.getElementById("summaryCards");
      target.innerHTML = "";
      for (const [label, value] of cards) {{
        const card = document.createElement("div");
        card.className = "card";
        card.innerHTML = `<div class="label">${{label}}</div><div class="value">${{value}}</div>`;
        target.appendChild(card);
      }}
      const reviewFirst = items
        .filter((item) => item.review_priority === "review_first")
        .slice(0, 3)
        .map((item) => `${{item.name}} (${{item.display_size}}) - ${{item.decision_focus}}`)
        .join("<br>");
      document.getElementById("reviewFirstPanel").innerHTML = reviewFirst
        ? `<strong>Review first:</strong><br>${{reviewFirst}}`
        : `<strong>Review first:</strong> No high-priority wins stand out in the current filtered view.`;
      document.getElementById("reasoningMeta").innerHTML =
        `<strong>Reasoning coverage:</strong> Codex Local processed ${{counts.codex_local || 0}} unit(s); Deterministic processed ${{counts.deterministic || 0}} unit(s); OpenAI API processed ${{counts.openai_api || 0}} unit(s). ` +
        `Fallback happened for ${{fallbackLimitCount + fallbackFailureCount}} unit(s): ${{fallbackLimitCount}} because the max_units limit was reached and ${{fallbackFailureCount}} because the primary provider was unavailable or failed.`;
    }}
    function renderBarChart(targetId, rows, formatter) {{
      const target = document.getElementById(targetId);
      target.innerHTML = "";
      const maxValue = Math.max(1, ...rows.map((row) => row.value));
      for (const row of rows) {{
        const wrap = document.createElement("div");
        wrap.className = "bar-row";
        wrap.innerHTML = `<div>${{titleCase(row.label)}}</div><div class="bar"><span style="width:${{Math.max(4, (row.value / maxValue) * 100)}}%"></span></div><div>${{formatter(row.value)}}</div>`;
        target.appendChild(wrap);
      }}
    }}
    function renderCharts(items) {{
      const categoryMap = {{}};
      const modeMap = {{}};
      for (const item of items) {{
        categoryMap[item.category] = (categoryMap[item.category] || 0) + item.total_size_bytes;
        modeMap[item.reasoning_provider] = (modeMap[item.reasoning_provider] || 0) + 1;
      }}
      const categoryRows = Object.entries(categoryMap).map(([label, value]) => ({{ label, value }})).sort((a, b) => b.value - a.value).slice(0, 8);
      const modeRows = Object.entries(modeMap).map(([label, value]) => ({{ label, value }})).sort((a, b) => b.value - a.value);
      renderBarChart("categoryChart", categoryRows, formatBytes);
      renderBarChart("modeChart", modeRows, (value) => String(value));
    }}
    function badge(type, value, extra = "") {{
      return `<span class="badge ${{
        type === "risk" ? `risk-${{value}}` : `confidence-${{value}}`
      }}">${{titleCase(value)}}${{extra}}</span>`;
    }}
    function renderTable(items) {{
      const tbody = document.getElementById("resultsBody");
      tbody.innerHTML = "";
      for (const item of items) {{
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${{item.name}}</td>
          <td>${{titleCase(item.review_priority)}} (${{item.review_priority_score}})</td>
          <td class="path">${{item.path}}</td>
          <td>${{titleCase(item.unit_type)}}</td>
          <td>${{titleCase(item.category)}}</td>
          <td>${{titleCase(item.zone)}}</td>
          <td>${{badge("risk", item.risk)}}</td>
          <td>${{badge("confidence", item.confidence_label, ` (${{item.confidence_score}})`)}}</td>
          <td>${{item.display_size}}</td>
          <td>${{item.file_count}}</td>
          <td>${{titleCase(item.reasoning_provider)}}</td>
          <td>${{item.fallback_provider ? titleCase(item.fallback_provider) : ""}}</td>
          <td>${{item.provider_failure_reason ? titleCase(item.provider_failure_reason) : ""}}</td>
          <td>${{item.decision_focus || ""}}</td>
          <td>${{item.recommendation}}</td>
          <td>${{item.reason_summary}}</td>
          <td>${{item.display_modified_at || ""}}</td>
          <td>${{titleCase(item.evidence_source)}}</td>
          <td><div class="actions"><button type="button" data-view="${{item.unit_id}}">Details</button><a href="${{item.open_uri}}">Open folder</a></div></td>
        `;
        tbody.appendChild(tr);
      }}
      for (const button of tbody.querySelectorAll("button[data-view]")) {{
        button.addEventListener("click", () => {{
          state.activeId = button.getAttribute("data-view");
          renderDetails();
        }});
      }}
    }}
    function renderDetails() {{
      const target = document.getElementById("detailPanel");
      const item = DATA.findings.find((entry) => entry.unit_id === state.activeId);
      if (!item) {{
        target.innerHTML = `<div class="meta">Select a cleanup unit to inspect deterministic evidence, reasoning output, uncertainty, counterarguments, citations, and fallback behavior.</div>`;
        return;
      }}
      const citationHtml = (item.web_citations || []).length
        ? `<ul class="list">${{item.web_citations.map((citation) => `<li><a href="${{citation.url}}">${{citation.title}}</a> - ${{citation.claim}}</li>`).join("")}}</ul>`
        : `<div class="meta">No supporting citations attached.</div>`;
      const sampleFiles = (item.sample_files || []).length
        ? `<ul class="list">${{item.sample_files.map((sample) => `<li>${{sample.path}} (${{formatBytes(sample.size_bytes)}})</li>`).join("")}}</ul>`
        : `<div class="meta">No sample files captured.</div>`;
      target.innerHTML = `
        <div><strong>Full path:</strong> <span class="path">${{item.path}}</span></div>
        <div><strong>Root path:</strong> <span class="path">${{item.root_path}}</span></div>
        <div><strong>Requested reasoning provider:</strong> ${{titleCase(item.requested_reasoning_provider || DATA.config.reasoning_provider)}}</div>
        <div><strong>Actual reasoning provider:</strong> ${{titleCase(item.reasoning_provider)}}</div>
        <div><strong>Fallback provider:</strong> ${{item.fallback_provider ? titleCase(item.fallback_provider) : "None"}}</div>
        <div><strong>Reasoning status:</strong> ${{titleCase(item.reasoning_status || "completed")}}</div>
        <div><strong>Review priority:</strong> ${{titleCase(item.review_priority)}} (${{item.review_priority_score}})</div>
        <div><strong>Decision focus:</strong> ${{item.decision_focus || "None"}}</div>
        <div><strong>Provider failure reason:</strong> ${{item.provider_failure_reason ? titleCase(item.provider_failure_reason) : "None"}}</div>
        <div><strong>Provider failure detail:</strong> ${{item.provider_failure_detail || "None"}}</div>
        <div><strong>Provider debug artifact:</strong> ${{item.provider_debug_artifact_path || "None"}}</div>
        <div><strong>Grouping logic:</strong> ${{item.grouping_logic}}</div>
        <div><strong>Reasoning:</strong> ${{item.llm_rationale}}</div>
        <div><strong>Uncertainty notes:</strong><ul class="list">${{(item.uncertainty_notes || []).map((note) => `<li>${{note}}</li>`).join("")}}</ul></div>
        <div><strong>Counterarguments:</strong><ul class="list">${{(item.counterarguments || []).map((note) => `<li>${{note}}</li>`).join("")}}</ul></div>
        <div><strong>Cleanup characterization:</strong> ${{(item.cleanup_characterization || []).map(titleCase).join(", ")}}</div>
        <div><strong>Used web support:</strong> ${{item.used_web_support ? "Yes" : "No"}}</div>
        <div><strong>Sample files:</strong>${{sampleFiles}}</div>
        <div><strong>Supporting citations:</strong>${{citationHtml}}</div>
        <div><strong>Deterministic evidence:</strong><pre>${{JSON.stringify(item.deterministic_evidence, null, 2)}}</pre></div>
      `;
    }}
    function renderAll() {{
      const items = filteredItems();
      renderSummary(items);
      renderCharts(items);
      renderTable(items);
      if (!items.find((item) => item.unit_id === state.activeId)) state.activeId = items[0] ? items[0].unit_id : null;
      renderDetails();
    }}
    for (const element of document.querySelectorAll("input, select")) {{
      element.addEventListener("input", renderAll);
      element.addEventListener("change", renderAll);
    }}
    document.getElementById("sortKey").addEventListener("change", (event) => {{
      state.sortKey = event.target.value;
      state.sortDirection = "desc";
      renderAll();
    }});
    for (const button of document.querySelectorAll("th button[data-sort]")) {{
      button.addEventListener("click", () => {{
        const nextKey = button.getAttribute("data-sort");
        if (state.sortKey === nextKey) {{
          state.sortDirection = state.sortDirection === "asc" ? "desc" : "asc";
        }} else {{
          state.sortKey = nextKey;
          state.sortDirection = nextKey === "name" || nextKey === "path" ? "asc" : "desc";
          document.getElementById("sortKey").value = nextKey;
        }}
        renderAll();
      }});
    }}
    populateFilters();
    renderAll();
  </script>
</body>
</html>
"""
