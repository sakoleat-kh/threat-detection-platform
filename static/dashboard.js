const DETECTION_RULES = [
    "ssh_brute_force", "successful_after_failures", "excessive_sudo", "new_user_creation",
    "directory_scanning", "sql_injection", "xss_attempt", "suspicious_user_agent"
];
const TACTIC_COLORS = ["#36A2EB", "#FF6384", "#FF9F40", "#FFCD56", "#4BC0C0", "#9966FF", "#C9CBCF"];

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
        ctx.fillStyle = "#495057";
        ctx.textAlign = "center";
        ctx.textBaseline = "bottom";
        meta.data.forEach((bar, i) => ctx.fillText(chart.data.datasets[0].data[i], bar.x, bar.y - 4));
        ctx.restore();
    }
};

function severityClass(severity) {
    switch (String(severity ?? "").toLowerCase()) {
        case "critical": case "high": return "bg-danger";
        case "medium": return "bg-warning text-dark";
        default: return "bg-secondary";
    }
}

function severityBadge(severity) {
    const badge = document.createElement("span");
    badge.className = `badge ${severityClass(severity)}`;
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
            data: { labels: ruleNames, datasets: [{ label: "Alerts", data: ruleCounts, backgroundColor: "rgba(54, 162, 235, 0.5)" }] },
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
                    datasets: [{ data: Object.values(byTactic), backgroundColor: tacticNames.map((_, i) => TACTIC_COLORS[i % TACTIC_COLORS.length]) }]
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
        raw.className = "bg-light border rounded p-3 mb-0";
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
async function refreshDashboard() {
    const button = $("refreshButton");
    button.disabled = true;
    const [statsOk, alertsOk] = await Promise.all([loadStats(), loadAlerts()]);
    button.disabled = false;

    if (statsOk && alertsOk) {
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

refreshDashboard();