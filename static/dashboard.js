// Rules configured in the backend. Used so rules with 0 alerts still appear.
// Any extra rule returned by /stats/ is added automatically.
const DETECTION_RULES = [
    "ssh_brute_force", "successful_after_failures", "excessive_sudo", "new_user_creation",
    "directory_scanning", "sql_injection", "xss_attempt", "suspicious_user_agent"
];
const TACTIC_COLORS = ["#36A2EB", "#FF6384", "#FF9F40", "#FFCD56", "#4BC0C0", "#9966FF", "#C9CBCF"];

// Chart colors for each theme.
const CHART_THEMES = {
    light: { text: "#495057", grid: "rgba(0, 0, 0, 0.1)", bar: "rgba(54, 162, 235, 0.5)", border: "#ffffff", label: "#495057", panel: "#ffffff" },
    dark: { text: "#aeb8c8", grid: "rgba(255, 255, 255, 0.08)", bar: "rgba(255, 159, 64, 0.85)", border: "#151c29", label: "#e6edf7", panel: "#1a2130" }
};

function chartTheme() {
    return CHART_THEMES[document.documentElement.getAttribute("data-bs-theme") === "dark" ? "dark" : "light"];
}

function applyChartTheme() {
    if (!Chart.defaults) return;
    Chart.defaults.color = chartTheme().text;
    Chart.defaults.borderColor = chartTheme().grid;
}

applyChartTheme();

let ruleChart = null, tacticChart = null, alertsRequestId = 0;
const $ = (id) => document.getElementById(id);

// Draws the value above each bar so zero-alert rules still show "0".
const valueLabels = {
    id: "valueLabels",
    afterDatasetsDraw(chart) {
        const meta = chart.getDatasetMeta(0);
        if (meta.hidden) return;
        const { ctx } = chart;
        ctx.save();
        ctx.font = "12px sans-serif";
        ctx.fillStyle = chartTheme().label;
        ctx.textAlign = "center";
        ctx.textBaseline = "bottom";
        meta.data.forEach((bar, i) => ctx.fillText(chart.data.datasets[0].data[i], bar.x, bar.y - 4));
        ctx.restore();
    }
};

function severityClass(severity) {
    const level = String(severity ?? "").toLowerCase();
    return ["critical", "high", "medium", "low"].includes(level) ? `tag-${level}` : "tag-unknown";
}

function severityBadge(severity) {
    const badge = document.createElement("span");
    badge.className = `sev-tag ${severityClass(severity)}`;
    badge.textContent = String(severity ?? "-").toUpperCase();
    return badge;
}

function showError(message) {
    const banner = $("errorBanner");
    banner.textContent = message;
    banner.classList.toggle("d-none", !message);
}

function fillSelect(select, values) {
    const current = select.value;
    const first = select.options[0];
    select.innerHTML = "";
    select.appendChild(first);
    for (const value of values) {
        const option = document.createElement("option");
        option.value = value;
        option.textContent = value;
        select.appendChild(option);
    }
    if (values.includes(current)) select.value = current;
}

function toggleChartEmpty(canvasId, emptyId, isEmpty) {
    $(canvasId).style.display = isEmpty ? "none" : "block";
    $(emptyId).style.display = isEmpty ? "flex" : "none";
}

// ---------- Statistics (GET /stats/) ----------
async function loadStats() {
    try {
        const response = await fetch("/stats/");
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const stats = await response.json();

        const byRule = stats.by_rule ?? {};
        const byTechnique = stats.by_technique ?? {};
        const byTactic = stats.by_tactic ?? {};

        // All configured rules, plus any extra rule the API returns.
        const ruleNames = [...DETECTION_RULES, ...Object.keys(byRule).filter((r) => !DETECTION_RULES.includes(r))];
        const ruleCounts = ruleNames.map((name) => byRule[name] ?? 0);

        const totalAlerts = Object.values(byRule).reduce((sum, n) => sum + n, 0);
        const rulesTriggered = ruleCounts.filter((n) => n > 0).length;
        const techniqueCount = Object.keys(byTechnique).length;
        const tacticNames = Object.keys(byTactic);

        // Summary cards
        $("totalAlerts").textContent = totalAlerts;
        $("totalRules").textContent = ruleNames.length;
        $("rulesTriggered").textContent = `${rulesTriggered} of ${ruleNames.length} have triggered alerts`;
        $("totalTechniques").textContent = techniqueCount;
        $("tacticsCovered").textContent = `Across ${tacticNames.length} tactic${tacticNames.length === 1 ? "" : "s"}`;

        // Filter dropdowns
        fillSelect($("ruleFilter"), ruleNames);
        fillSelect($("tacticFilter"), tacticNames);

        // Rule chart (all rules, zeros included)
        if (ruleChart) ruleChart.destroy();
        ruleChart = new Chart($("ruleChart"), {
            type: "bar",
            data: { labels: ruleNames, datasets: [{ label: "Alerts", data: ruleCounts, backgroundColor: chartTheme().bar }] },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                layout: { padding: { top: 18 } },
                plugins: { legend: { display: true } },
                scales: { y: { beginAtZero: true, ticks: { precision: 0 } } }
            },
            plugins: [valueLabels]
        });
        toggleChartEmpty("ruleChart", "ruleChartEmpty", false);

        // Tactic chart (stats.by_tactic)
        if (tacticChart) { tacticChart.destroy(); tacticChart = null; }
        if (tacticNames.length === 0) {
            toggleChartEmpty("tacticChart", "tacticChartEmpty", true);
        } else {
            toggleChartEmpty("tacticChart", "tacticChartEmpty", false);
            tacticChart = new Chart($("tacticChart"), {
                type: "doughnut",
                data: {
                    labels: tacticNames,
                    datasets: [{ data: Object.values(byTactic), backgroundColor: tacticNames.map((_, i) => TACTIC_COLORS[i % TACTIC_COLORS.length]), borderColor: chartTheme().border, borderWidth: 2 }]
                },
                options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: "top" } } }
            });
        }
        return true;
    } catch (error) {
        console.error("Failed to load statistics:", error);
        return false;
    }
}

// ---------- Alerts (GET /alerts/ with filters) ----------
function buildAlertsUrl() {
    const params = new URLSearchParams();
    const filters = {
        rule_id: $("ruleFilter").value,
        tactic: $("tacticFilter").value,
        start_date: $("startDate").value,
        end_date: $("endDate").value
    };
    for (const [key, value] of Object.entries(filters)) {
        if (value) params.set(key, value);
    }
    params.set("limit", "100");
    return `/alerts/?${params.toString()}`;
}

function messageRow(text, cssClass) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 7;
    cell.className = `text-center ${cssClass}`;
    cell.textContent = text;
    row.appendChild(cell);
    return row;
}

function makeCell(text, subText) {
    const cell = document.createElement("td");
    cell.textContent = text ?? "-";
    if (subText) {
        const sub = document.createElement("div");
        sub.className = "small text-muted";
        sub.textContent = subText;
        cell.appendChild(sub);
    }
    return cell;
}

async function loadAlerts() {
    const tableBody = $("alertsTableBody");
    const alertCount = $("alertCount");
    const requestId = ++alertsRequestId;

    const start = $("startDate").value, end = $("endDate").value;
    if (start && end && start > end) {
        $("filterMessage").textContent = "Start date must be on or before end date.";
        return true;
    }
    $("filterMessage").textContent = "";

    tableBody.replaceChildren(messageRow("Loading alerts...", "text-muted"));

    try {
        const response = await fetch(buildAlertsUrl());
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const alerts = await response.json();
        if (requestId !== alertsRequestId) return true; // a newer request replaced this one

        alertCount.textContent = `${alerts.length} alert${alerts.length === 1 ? "" : "s"}`;
        alertCount.className = `badge ${alerts.length ? "text-bg-danger" : "text-bg-secondary"}`;

        if (alerts.length === 0) {
            tableBody.replaceChildren(messageRow("No alerts found.", "text-muted"));
            return true;
        }

        const rows = alerts.map((alert) => {
            const row = document.createElement("tr");
            row.className = "alert-row-clickable";
            row.addEventListener("click", () => openAlertDetail(alert.id));

            const severityCell = document.createElement("td");
            severityCell.appendChild(severityBadge(alert.severity));

            row.append(
                makeCell(alert.id),
                makeCell(alert.rule_id),
                severityCell,
                makeCell(alert.technique_id, alert.technique_name),
                makeCell(alert.tactic),
                makeCell(alert.source_ip ?? alert.source_type, alert.source_ip ? alert.source_type : null),
                makeCell(alert.username)
            );
            return row;
        });
        tableBody.replaceChildren(...rows);
        return true;
    } catch (error) {
        console.error("Failed to load alerts:", error);
        if (requestId === alertsRequestId) {
            tableBody.replaceChildren(messageRow("Failed to load alerts.", "text-danger"));
            alertCount.textContent = "Error";
            alertCount.className = "badge text-bg-danger";
        }
        return false;
    }
}

// ---------- Alert detail (GET /alerts/{id}) ----------
function detailRow(label, valueNode) {
    const row = document.createElement("div");
    row.className = "row mb-2";
    const labelEl = document.createElement("div");
    labelEl.className = "col-sm-4 fw-semibold";
    labelEl.textContent = label;
    const valueEl = document.createElement("div");
    valueEl.className = "col-sm-8";
    if (typeof valueNode === "string" || valueNode == null) valueEl.textContent = valueNode ?? "-";
    else valueEl.appendChild(valueNode);
    row.append(labelEl, valueEl);
    return row;
}

async function openAlertDetail(alertId) {
    const body = $("alertDetailBody");
    body.innerHTML = `
        <div class="text-center py-4">
            <div class="spinner-border" role="status"><span class="visually-hidden">Loading...</span></div>
            <p class="mt-2 mb-0">Loading alert details...</p>
        </div>`;
    bootstrap.Modal.getOrCreateInstance($("alertDetailModal")).show();

    try {
        const response = await fetch(`/alerts/${alertId}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const alert = await response.json();

        const rows = [
            detailRow("Alert ID", String(alert.id)),
            detailRow("Rule ID", alert.rule_id),
            detailRow("Rule Name", alert.rule_name),
            detailRow("Severity", severityBadge(alert.severity)),
            detailRow("Description", alert.description),
            detailRow("MITRE Technique ID", alert.technique_id),
            detailRow("MITRE Technique", alert.technique_name),
            detailRow("MITRE Tactic", alert.tactic),
            detailRow("Source Type", alert.source_type),
            detailRow("Source IP", alert.source_ip),
            detailRow("Username", alert.username),
            detailRow("Event Timestamp", alert.event_timestamp),
            detailRow("Created At", alert.created_at)
        ];

        const rawTitle = document.createElement("h6");
        rawTitle.className = "mt-4";
        rawTitle.textContent = "Raw Event JSON";
        const raw = document.createElement("pre");
        raw.className = "bg-body-tertiary border rounded p-3 mb-0";
        raw.style.maxHeight = "300px";
        raw.style.overflow = "auto";
        raw.textContent = JSON.stringify(alert.raw_event_json ?? {}, null, 2);

        body.replaceChildren(...rows, rawTitle, raw);
    } catch (error) {
        console.error("Failed to load alert details:", error);
        body.innerHTML = '<div class="alert alert-danger mb-0">Failed to load alert details.</div>';
    }
}

// ---------- Refresh and events ----------
// ---------- Alert Severity Distribution (doughnut) ----------
let severityChart = null;

function renderSeverityChart(counts) {
    const names = ["Critical", "High", "Medium", "Low"];
    const values = [counts.critical, counts.high, counts.medium, counts.low];
    const total = values.reduce((sum, n) => sum + n, 0);

    if (severityChart) { severityChart.destroy(); severityChart = null; }
    toggleChartEmpty("severityChart", "severityChartEmpty", total === 0);
    if (total === 0) return;

    severityChart = new Chart($("severityChart"), {
        type: "doughnut",
        data: {
            labels: names.map((name, i) => `${name}  ${Math.round((values[i] / total) * 100)}%`),
            datasets: [{ data: values, backgroundColor: ["#d32f2f", "#f57c1f", "#f5b014", "#4caf50"], borderColor: chartTheme().panel, borderWidth: 2 }]
        },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: "right" } } }
    });
}

// ---------- Severity cards (counted from GET /alerts/, 100 per page) ----------
async function loadSeverityCounts() {
    try {
        const counts = { critical: 0, high: 0, medium: 0, low: 0 };
        for (let page = 0; page < 50; page++) {
            const response = await fetch(`/alerts/?limit=100&offset=${page * 100}`);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            const alerts = await response.json();
            for (const alert of alerts) {
                const level = String(alert.severity ?? "").toLowerCase();
                if (level in counts) counts[level] += 1;
            }
            if (alerts.length < 100) break;
        }
        $("sevCritical").textContent = counts.critical;
        $("sevHigh").textContent = counts.high;
        $("sevMedium").textContent = counts.medium;
        $("sevLow").textContent = counts.low;
        renderSeverityChart(counts);
        return true;
    } catch (error) {
        console.error("Failed to load severity counts:", error);
        return false;
    }
}

// ---------- Active Alerts panel (newest first, 5 per page) ----------
const ACTIVE_PAGE_SIZE = 5;
let activePage = 0;                     // 0 = the newest alerts

function formatAlertTime(value) {
    const date = new Date(value);
    if (!value || Number.isNaN(date.getTime())) return value ?? "-";
    return date.toLocaleString([], { year: "numeric", month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
}

async function loadActiveAlerts() {
    try {
        const statsResponse = await fetch("/stats/");
        if (!statsResponse.ok) throw new Error(`HTTP ${statsResponse.status}`);
        const stats = await statsResponse.json();
        const total = Object.values(stats.by_rule ?? {}).reduce((sum, n) => sum + n, 0);

        const pages = Math.max(1, Math.ceil(total / ACTIVE_PAGE_SIZE));
        activePage = Math.min(activePage, pages - 1);
        const end = total - activePage * ACTIVE_PAGE_SIZE;           // newest alert is the last row
        const start = Math.max(0, end - ACTIVE_PAGE_SIZE);

        let alerts = [];
        if (total > 0) {
            const response = await fetch(`/alerts/?limit=${end - start}&offset=${start}`);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            alerts = (await response.json()).reverse();
        }

        const body = $("activeBody");
        if (alerts.length === 0) {
            const row = document.createElement("tr");
            const cell = document.createElement("td");
            cell.colSpan = 6;
            cell.className = "text-center text-muted";
            cell.textContent = "No alerts found.";
            row.appendChild(cell);
            body.replaceChildren(row);
        } else {
            body.replaceChildren(...alerts.map((alert) => {
                const row = document.createElement("tr");
                row.className = "alert-row-clickable";
                row.addEventListener("click", () => openAlertDetail(alert.id));

                const dotCell = document.createElement("td");
                const dot = document.createElement("span");
                dot.className = `sev-dot dot-${severityClass(alert.severity).replace("tag-", "")}`;
                dotCell.appendChild(dot);

                const severityCell = document.createElement("td");
                severityCell.appendChild(severityBadge(alert.severity));

                row.append(
                    makeCell(formatAlertTime(alert.event_timestamp)),
                    dotCell,
                    makeCell(alert.rule_name ?? alert.rule_id),
                    severityCell,
                    makeCell(alert.source_ip ?? alert.source_type, alert.source_ip ? alert.source_type : null),
                    makeCell(alert.technique_id, alert.technique_name)
                );
                return row;
            }));
        }

        const first = total === 0 ? 0 : activePage * ACTIVE_PAGE_SIZE + 1;
        const last = Math.min(total, (activePage + 1) * ACTIVE_PAGE_SIZE);
        $("activeRange").textContent = total === 0 ? "0 alerts" : `${first}-${last} of ${total}`;
        $("activePrev").disabled = activePage === 0;
        $("activeNext").disabled = activePage >= pages - 1;
        return true;
    } catch (error) {
        console.error("Failed to load active alerts:", error);
        return false;
    }
}

$("activePrev").addEventListener("click", () => { activePage = Math.max(0, activePage - 1); loadActiveAlerts(); });
$("activeNext").addEventListener("click", () => { activePage += 1; loadActiveAlerts(); });

async function refreshDashboard() {
    const button = $("refreshButton");
    button.disabled = true;
    const [statsOk, alertsOk, severityOk, activeOk] = await Promise.all([loadStats(), loadAlerts(), loadSeverityCounts(), loadActiveAlerts()]);
    button.disabled = false;

    if (statsOk && alertsOk && severityOk && activeOk) {
        showError("");
        $("lastUpdated").textContent = `Updated ${new Date().toLocaleTimeString()}`;
    } else {
        showError("Failed to load dashboard data. Check that the API is running, then press Refresh.");
    }
}

$("refreshButton").addEventListener("click", refreshDashboard);
$("applyFiltersButton").addEventListener("click", loadAlerts);
$("clearFiltersButton").addEventListener("click", () => {
    for (const id of ["ruleFilter", "tacticFilter", "startDate", "endDate"]) $(id).value = "";
    loadAlerts();
});

// ---------- Upload a log (POST /ingest/) ----------
// Which rules belong to which log type (used only to fill the dropdown).
const RULES_BY_LOG = {
    auth: ["ssh_brute_force", "successful_after_failures", "excessive_sudo", "new_user_creation"],
    access: ["directory_scanning", "sql_injection", "xss_attempt", "suspicious_user_agent"]
};

function fillUploadRules() {
    const rules = RULES_BY_LOG[$("uploadType").value] ?? [];
    $("uploadRule").replaceChildren(
        new Option("All rules for this log", "all"),
        ...rules.map((rule) => new Option(rule, rule))
    );
}

function showUploadResult(kind, message) {
    const box = $("uploadResult");
    box.className = `alert alert-${kind} mt-3 mb-0`;
    box.textContent = message;
}

function describeError(body, status) {
    const detail = body?.detail;
    if (Array.isArray(detail)) return detail.map((item) => item.msg).join("; ");
    if (typeof detail === "string") return detail;
    return `HTTP ${status}`;
}

async function uploadLog() {
    const file = $("uploadFile").files[0];
    if (!file) {
        showUploadResult("warning", "Choose a log file first.");
        return;
    }

    const maxValue = $("uploadMax").value.trim();
    if (maxValue !== "" && !(Number.isInteger(Number(maxValue)) && Number(maxValue) >= 1)) {
        showUploadResult("warning", "Max new alerts must be a whole number of 1 or more, or left empty.");
        return;
    }

    const rule = $("uploadRule").value;
    const form = new FormData();
    form.append("file", file);
    form.append("log_type", $("uploadType").value);
    form.append("rule", rule);
    if (maxValue !== "") form.append("max_alerts", maxValue);

    $("uploadButton").disabled = true;
    $("uploadSpinner").classList.remove("d-none");

    try {
        const response = await fetch("/ingest/", { method: "POST", body: form });
        const body = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(describeError(body, response.status));

        const lines = body.lines_processed ?? 0;
        const found = body.alerts_generated ?? 0;
        const saved = body.alerts_saved;

        if (saved === undefined) {
            showUploadResult("info", `Processed ${lines} lines and found ${found} alerts.`);
        } else if (saved > 0) {
            showUploadResult("success", `Saved ${saved} new alert${saved === 1 ? "" : "s"} (${found} found in ${lines} lines).`);
        } else if (found > 0) {
            showUploadResult("info", `No new alerts: all ${found} alerts found in this file are already stored.`);
        } else {
            showUploadResult("info", `No alerts found in ${lines} lines${rule === "all" ? "" : ` for ${rule}`}. Check that the log type matches the file.`);
        }

        await refreshDashboard();
    } catch (error) {
        console.error("Upload failed:", error);
        showUploadResult("danger", `Upload failed: ${error.message}`);
    } finally {
        $("uploadButton").disabled = false;
        $("uploadSpinner").classList.add("d-none");
    }
}

$("uploadType").addEventListener("change", fillUploadRules);
$("uploadFile").addEventListener("change", () => {
    const name = ($("uploadFile").files[0]?.name ?? "").toLowerCase();
    if (name.includes("access")) $("uploadType").value = "access";
    else if (name.includes("auth")) $("uploadType").value = "auth";
    fillUploadRules();
});
$("uploadButton").addEventListener("click", uploadLog);
fillUploadRules();

let autoRefreshTimer = null;
$("autoRefresh").addEventListener("change", () => {
    clearInterval(autoRefreshTimer);
    autoRefreshTimer = $("autoRefresh").checked ? setInterval(refreshDashboard, 5000) : null;
});

document.addEventListener("themechange", () => {
    applyChartTheme();
    refreshDashboard();          // redraw the charts with the new colors
});

refreshDashboard();