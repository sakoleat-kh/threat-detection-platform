// Live view of the alerts table, read from GET /stats/ and GET /alerts/.
const PAGE_SIZE = 100;            // the API allows at most 100 rows per request
const AUTO_REFRESH_MS = 5000;
const COLUMNS = [
    "id", "rule_id", "rule_name", "severity", "description", "technique_id", "technique_name",
    "tactic", "source_type", "source_ip", "username", "event_timestamp", "created_at", "raw_event_json"
];
const CLIPPED = new Set(["description", "raw_event_json", "technique_name"]);

const $ = (id) => document.getElementById(id);
let timer = null;
let loading = false;

function showError(message) {
    const banner = $("errorBanner");
    banner.textContent = message;
    banner.classList.toggle("d-none", !message);
}

function makeCell(column, value) {
    const cell = document.createElement("td");
    const text = value === null || value === undefined
        ? "NULL"
        : (typeof value === "object" ? JSON.stringify(value) : String(value));

    if (value === null || value === undefined) cell.className = "text-muted fst-italic";

    if (CLIPPED.has(column)) {
        const span = document.createElement("span");
        span.className = "cell-clip";
        span.textContent = text;
        span.title = text;
        cell.appendChild(span);
    } else {
        cell.textContent = text;
        cell.classList.add("text-nowrap");
    }
    return cell;
}

async function loadRows() {
    if (loading) return;
    loading = true;
    try {
        const statsResponse = await fetch("/stats/");
        if (!statsResponse.ok) throw new Error(`HTTP ${statsResponse.status}`);
        const stats = await statsResponse.json();
        const total = Object.values(stats.by_rule ?? {}).reduce((sum, n) => sum + n, 0);

        const offset = Math.max(0, total - PAGE_SIZE);
        const response = await fetch(`/alerts/?limit=${PAGE_SIZE}&offset=${offset}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const rows = (await response.json()).reverse();   // newest first

        const headRow = document.createElement("tr");
        for (const column of COLUMNS) {
            const th = document.createElement("th");
            th.textContent = column;
            th.className = "text-nowrap";
            headRow.appendChild(th);
        }
        $("tableHead").replaceChildren(headRow);

        if (rows.length === 0) {
            const row = document.createElement("tr");
            const cell = document.createElement("td");
            cell.colSpan = COLUMNS.length;
            cell.className = "text-center text-muted";
            cell.textContent = "The alerts table is empty.";
            row.appendChild(cell);
            $("tableBody").replaceChildren(row);
        } else {
            $("tableBody").replaceChildren(...rows.map((alert) => {
                const row = document.createElement("tr");
                for (const column of COLUMNS) row.appendChild(makeCell(column, alert[column]));
                return row;
            }));
        }

        $("rowInfo").textContent = `Showing ${rows.length} of ${total} rows`;
        $("rowInfo").className = `badge ${total ? "text-bg-primary" : "text-bg-secondary"}`;
        $("lastUpdated").textContent = `Updated ${new Date().toLocaleTimeString()}`;
        showError("");
    } catch (error) {
        console.error("Failed to load rows:", error);
        showError("Failed to load database rows. Check that the API is running.");
    } finally {
        loading = false;
    }
}

function setAutoRefresh() {
    clearInterval(timer);
    timer = $("autoRefresh").checked ? setInterval(loadRows, AUTO_REFRESH_MS) : null;
}

$("refreshButton").addEventListener("click", loadRows);
$("autoRefresh").addEventListener("change", setAutoRefresh);

loadRows();
setAutoRefresh();